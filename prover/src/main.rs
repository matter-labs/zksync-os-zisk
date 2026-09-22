//! ZiSK Prover Service for ZKsync OS
//!
//! External prover that polls the ZKsync OS server for ZiSK batch data,
//! generates STARK + SNARK proofs with `cargo-zisk`, and submits the results
//! back to the server for multi-proof composition.
//!
//! The deployed mode is `--coordinator-url`: the daemon shells `cargo-zisk
//! remote` against a resident `zisk-coordinator` whose worker keeps the
//! proving keys and the GPU loaded for the service lifetime. Without it the
//! daemon runs one `cargo-zisk` process per proof, which loads the keys on
//! every invocation.
//!
//! Two modes, matching the server's `zisk_aggregation` setting:
//! - Per-batch (default): each batch is proven with the PLONK wrap and the
//!   768-byte SNARK is submitted — one ZiSK proof per batch on L1.
//! - Aggregated (`--aggregation`, with `--aggregator-elf`): each batch is
//!   proven WITHOUT the wrap and the raw `vadcop_final` stream is
//!   submitted; the daemon also polls `/ZiSK-AGG` for range jobs, verifies
//!   the range's streams inside the aggregator guest, and submits one
//!   PLONK-wrapped range proof — one ZiSK proof per Airbender SNARK range.

use zksync_os_zisk_prover_service::{prover, sequencer_client};

use clap::Parser;
use std::path::PathBuf;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Parser, Debug)]
#[command(
    name = "zksync-os-zisk-prover-service",
    about = "ZiSK prover for ZKsync OS"
)]
struct Args {
    /// Sequencer URL(s) to poll for work: comma-separated, or the flag
    /// repeated. Several sequencers are polled round-robin; each supports
    /// Basic Auth: http://user:pass@host:port
    ///
    ///   --sequencer-urls http://localhost:3124,http://user:pass@other:3124
    #[arg(
        short,
        long,
        alias = "sequencer-url",
        value_delimiter = ',',
        num_args = 1..,
        required = true
    )]
    sequencer_urls: Vec<String>,

    /// Path to the pinned `cargo-zisk` binary. The coordinator backend uses
    /// its `remote` subcommands; the spawn backend proves with it directly.
    #[arg(long)]
    zisk_binary: PathBuf,

    /// Path to the ZiSK guest ELF binary.
    #[arg(long)]
    elf_path: PathBuf,

    /// Path to the ZiSK STARK proving key directory. Required unless
    /// `--coordinator-url` moves the keys to a resident worker.
    #[arg(long, required_unless_present = "coordinator_url")]
    proving_key: Option<PathBuf>,

    /// Path to the ZiSK PLONK proving key directory (cargo-zisk `-w`).
    /// Required unless `--coordinator-url` moves the keys to a resident
    /// worker.
    #[arg(
        long,
        alias = "proving-key-snark",
        required_unless_present = "coordinator_url"
    )]
    proving_key_plonk: Option<PathBuf>,

    /// gRPC URL of a resident `zisk-coordinator` (its client API port, 7000
    /// by default). The daemon uploads and sets up the ELFs through
    /// `cargo-zisk remote` and proves against that service; the proving keys
    /// and GPU live on its worker, so they load once instead of once per
    /// proof. Without this flag the daemon runs one `cargo-zisk` process per
    /// proof.
    #[arg(
        long,
        env = "ZISK_COORDINATOR_URL",
        conflicts_with_all = ["proving_key", "proving_key_plonk", "no_gpu", "asm_emulator"]
    )]
    coordinator_url: Option<String>,

    /// Aggregated mode: prove batches WITHOUT the PLONK wrap and submit
    /// their vadcop_final streams; poll /ZiSK-AGG for range jobs and prove
    /// them with the aggregator guest. The server must run with
    /// zisk_aggregation.enabled.
    #[arg(long, requires = "aggregator_elf")]
    aggregation: bool,

    /// Path to the ZiSK aggregator guest ELF (required with --aggregation).
    #[arg(long, requires = "aggregation")]
    aggregator_elf: Option<PathBuf>,

    /// Disable GPU proving (cargo-zisk runs CPU-only).
    #[arg(long)]
    no_gpu: bool,

    /// Use the ASM emulator for witness generation instead of the standard
    /// emulator (`--emulator`). Faster, but requires a high memlock ulimit
    /// that is often unavailable in containers.
    #[arg(long)]
    asm_emulator: bool,

    /// Directory for intermediate proof files.
    #[arg(long, default_value = "/tmp/zisk_proofs")]
    work_dir: PathBuf,

    /// Poll interval in seconds when no work is available.
    #[arg(long, default_value_t = 5)]
    poll_interval_secs: u64,

    /// Number of proofs to generate before exiting (0 = unlimited).
    #[arg(long, default_value_t = 0)]
    iterations: u64,

    /// Supported VK hashes (hex, 0x-prefixed). If not specified, accepts all.
    /// Pass multiple times: --supported-vk 0xabc... --supported-vk 0xdef...
    /// Or load from a file with --vk-hashes-file.
    #[arg(long = "supported-vk")]
    supported_vk_hashes: Vec<String>,

    /// Path to a file containing supported VK hashes (one per line).
    /// Lines starting with # are ignored. Combined with --supported-vk.
    #[arg(long)]
    vk_hashes_file: Option<PathBuf>,

    /// Prometheus metrics listen address.
    #[arg(long, default_value = "0.0.0.0:3313")]
    metrics_address: String,

    /// Prover identity reported to the sequencer's job API. Used for
    /// assignment attribution in fleet deployments; defaults to the machine
    /// hostname so concurrent daemons are distinguishable in server logs.
    #[arg(long)]
    prover_id: Option<String>,
}

/// What one poll of one sequencer amounted to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Poll {
    /// A proof was generated and submitted.
    Proved,
    /// The sequencer had no work.
    Idle,
    /// An attempt failed or a job was skipped; poll again without waiting,
    /// as the single-sequencer loop always did.
    Retry,
    /// Shutdown was requested mid-proof.
    Cancelled,
}

/// Decides when the round-robin loop sleeps: only once every sequencer in a
/// row came back idle, so each sequencer still sees one poll per interval
/// and one chain's backlog never starves another's. A proof resets the
/// streak; a retry leaves it alone.
struct IdleCycle {
    sequencers: usize,
    idle_streak: usize,
}

impl IdleCycle {
    fn new(sequencers: usize) -> Self {
        Self {
            sequencers: sequencers.max(1),
            idle_streak: 0,
        }
    }

    /// Records the outcome; true when the caller should sleep for the poll
    /// interval before the next sequencer.
    fn record(&mut self, outcome: Poll) -> bool {
        match outcome {
            Poll::Idle => {
                self.idle_streak += 1;
                if self.idle_streak >= self.sequencers {
                    self.idle_streak = 0;
                    true
                } else {
                    false
                }
            }
            Poll::Proved => {
                self.idle_streak = 0;
                false
            }
            Poll::Retry | Poll::Cancelled => false,
        }
    }
}

/// Resolve the prover identity: explicit flag, else hostname, else a fixed
/// fallback.
fn resolve_prover_id(args: &Args) -> String {
    if let Some(ref id) = args.prover_id {
        return id.clone();
    }
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "zisk_prover".to_string())
}

/// Canonicalize a VK hash for comparison: strip an optional `0x`/`0X`
/// prefix and lowercase. The server reports hashes 0x-prefixed
/// (`format!("0x{h}")`), so the operator-supplied filter list and the
/// per-batch hash are canonicalized the same way before comparing; a bare
/// hex value in `--supported-vk` then matches instead of silently skipping
/// every batch.
fn normalize_vk_hash(raw: &str) -> String {
    raw.strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw)
        .to_lowercase()
}

fn load_supported_vk_hashes(args: &Args) -> anyhow::Result<Vec<String>> {
    let mut raw: Vec<String> = args.supported_vk_hashes.clone();

    if let Some(ref path) = args.vk_hashes_file {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        raw.push(line.to_string());
                    }
                }
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), "failed to read VK hashes file: {e}");
            }
        }
    }

    // Normalize + validate up front so a formatting typo fails fast at
    // startup instead of silently skipping every batch at run time.
    let mut hashes = Vec::with_capacity(raw.len());
    for entry in raw {
        let norm = normalize_vk_hash(&entry);
        anyhow::ensure!(
            norm.len() == 64 && norm.bytes().all(|b| b.is_ascii_hexdigit()),
            "malformed VK hash filter entry {entry:?}: expected a 32-byte \
             hex hash (64 hex chars, optional 0x prefix)"
        );
        hashes.push(norm);
    }

    // Vec::dedup only drops CONSECUTIVE duplicates, and the CLI and file
    // sources are concatenated, so sort first to catch a hash listed in both.
    hashes.sort();
    hashes.dedup();
    Ok(hashes)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let supported_vks = load_supported_vk_hashes(&args)?;
    let prover_id = resolve_prover_id(&args);

    tracing::info!(
        prover_id = %prover_id,
        zisk_binary = %args.zisk_binary.display(),
        elf_path = %args.elf_path.display(),
        coordinator_url = ?args.coordinator_url,
        aggregation = args.aggregation,
        aggregator_elf = ?args.aggregator_elf,
        supported_vk_hashes = ?supported_vks,
        vk_filter = if supported_vks.is_empty() { "disabled (accepts all)" } else { "enabled" },
        "Starting ZiSK prover service"
    );

    // Select the proving backend. A coordinator URL moves the keys and the
    // GPU to the resident worker; without one, this process owns both.
    let backend = match args.coordinator_url.clone() {
        Some(url) => prover::ProvingBackend::Coordinator { url },
        None => prover::ProvingBackend::Spawn(prover::SpawnBackend {
            proving_key: args
                .proving_key
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--proving-key is required"))?,
            proving_key_plonk: args
                .proving_key_plonk
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--proving-key-plonk is required"))?,
            gpu: !args.no_gpu,
            asm_emulator: args.asm_emulator,
        }),
    };

    // Validate paths.
    let mut required_paths = vec![
        ("zisk_binary", &args.zisk_binary),
        ("elf_path", &args.elf_path),
    ];
    if let Some(ref aggregator_elf) = args.aggregator_elf {
        required_paths.push(("aggregator_elf", aggregator_elf));
    }
    if let prover::ProvingBackend::Spawn(ref spawn) = backend {
        required_paths.push(("proving_key", &spawn.proving_key));
        required_paths.push(("proving_key_plonk", &spawn.proving_key_plonk));
    }
    for (name, path) in required_paths {
        anyhow::ensure!(path.exists(), "{name} does not exist: {}", path.display());
    }

    // Start Prometheus metrics server.
    let metrics_addr: std::net::SocketAddr = args.metrics_address.parse()?;
    let exporter = vise_exporter::MetricsExporter::default();
    tokio::spawn(exporter.start(metrics_addr));
    tracing::info!(address = %metrics_addr, "metrics server started");

    // One client per sequencer, polled round-robin below. `url()` has the
    // credentials stripped, so the list is safe to log.
    let clients = args
        .sequencer_urls
        .iter()
        .map(|url| sequencer_client::SequencerClient::new(url, &prover_id, &supported_vks))
        .collect::<anyhow::Result<Vec<_>>>()?;
    tracing::info!(
        sequencers = ?clients.iter().map(|c| c.url()).collect::<Vec<_>>(),
        "connected to sequencers"
    );

    let prover = prover::ZiskProver::new(
        args.zisk_binary,
        args.elf_path,
        args.aggregator_elf.clone(),
        backend,
        args.work_dir,
    );

    let poll_interval = Duration::from_secs(args.poll_interval_secs);
    let mut proofs_generated: u64 = 0;

    // Graceful shutdown via CancellationToken.
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => tracing::info!("received SIGINT"),
            _ = sigterm.recv() => tracing::info!("received SIGTERM"),
        }
        cancel_clone.cancel();
    });

    // One-time ROM setup for the guest ELF(s) (idempotent, cheap when cached).
    // Against a coordinator the setup needs a registered worker, and a worker
    // registers only after it has loaded its keys, which takes minutes on a
    // cold start. Retry until then instead of exiting into a restart loop. The
    // spawn backend fails fast: its setup depends on nothing remote.
    let wait_for_coordinator = args.coordinator_url.is_some();
    let setup_retry = poll_interval.max(Duration::from_secs(15));
    loop {
        let result = async {
            if !prover.ensure_program_setup(&cancel).await? {
                return Ok(false);
            }
            if args.aggregation && !prover.ensure_aggregator_program_setup(&cancel).await? {
                return Ok(false);
            }
            anyhow::Ok(true)
        }
        .await;
        match result {
            Ok(true) => break,
            Ok(false) => {
                tracing::info!("cancelled during program-setup, exiting");
                return Ok(());
            }
            Err(e) if wait_for_coordinator => {
                tracing::warn!(
                    retry_secs = setup_retry.as_secs(),
                    "program-setup against the coordinator failed (no worker registered yet?), retrying: {e:#}"
                );
                tokio::select! {
                    _ = tokio::time::sleep(setup_retry) => {}
                    _ = cancel.cancelled() => {
                        tracing::info!("cancelled while waiting for the coordinator, exiting");
                        return Ok(());
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }

    // Poll the sequencers round-robin. A sequencer with work is served at
    // once; the daemon sleeps only after a full cycle in which none had any.
    let mut idle_cycle = IdleCycle::new(clients.len());
    for client in clients.iter().cycle() {
        if cancel.is_cancelled() {
            tracing::info!("shutdown requested, exiting");
            break;
        }

        let outcome =
            poll_sequencer(client, &prover, args.aggregation, &supported_vks, &cancel).await;
        match outcome {
            Poll::Cancelled => break,
            Poll::Proved => {
                proofs_generated += 1;
                if args.iterations > 0 && proofs_generated >= args.iterations {
                    tracing::info!(proofs_generated, "iteration limit reached");
                    break;
                }
            }
            Poll::Idle | Poll::Retry => {}
        }
        if idle_cycle.record(outcome) {
            tokio::select! {
                _ = tokio::time::sleep(poll_interval) => {}
                _ = cancel.cancelled() => break,
            }
        }
    }

    Ok(())
}

/// One pass over one sequencer: in aggregated mode a range job first, since
/// a formed range is the last missing piece of its MultiProof, then a batch.
/// A transient proof or submit failure is logged and reported as `Retry`
/// instead of killing the daemon, so one bad run never takes down the lane.
async fn poll_sequencer(
    client: &sequencer_client::SequencerClient,
    prover: &prover::ZiskProver,
    aggregation: bool,
    supported_vks: &[String],
    cancel: &CancellationToken,
) -> Poll {
    let sequencer = client.url();

    if aggregation {
        match client.pick_next_aggregation_job().await {
            Ok(Some(job)) => {
                if !supported_vks.is_empty() {
                    let vk_norm = normalize_vk_hash(&job.vk_hash);
                    if job.vk_hash.is_empty() || !supported_vks.contains(&vk_norm) {
                        tracing::warn!(
                            sequencer,
                            from = job.from_batch,
                            to = job.to_batch,
                            vk_hash = %job.vk_hash,
                            "aggregation server returned an unsupported ZiSK identity; skipping"
                        );
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        return Poll::Retry;
                    }
                }
                tracing::info!(
                    sequencer,
                    from = job.from_batch,
                    to = job.to_batch,
                    proofs = job.streams.len(),
                    vk_hash = %job.vk_hash,
                    "picked ZiSK aggregation range"
                );
                let streams: Vec<Vec<u8>> =
                    job.streams.into_iter().map(|(_, stream)| stream).collect();
                let result = match prover
                    .generate_aggregated_proof(&streams, job.from_batch, job.to_batch, cancel)
                    .await
                {
                    Ok(Some(result)) => result,
                    Ok(None) => {
                        tracing::info!("aggregated proof cancelled, exiting");
                        return Poll::Cancelled;
                    }
                    Err(e) => {
                        tracing::warn!(
                            sequencer,
                            from = job.from_batch,
                            to = job.to_batch,
                            "aggregated proof generation failed, will retry: {e:#}"
                        );
                        return Poll::Retry;
                    }
                };
                if let Err(e) = client
                    .submit_aggregated_proof(
                        job.from_batch,
                        job.to_batch,
                        &result.proof,
                        &result.public_values,
                    )
                    .await
                {
                    tracing::warn!(
                        sequencer,
                        from = job.from_batch,
                        to = job.to_batch,
                        "aggregated proof submit failed, will retry: {e:#}"
                    );
                    return Poll::Retry;
                }
                prover
                    .cleanup_range_work_dir(job.from_batch, job.to_batch)
                    .await;
                tracing::info!(
                    sequencer,
                    from = job.from_batch,
                    to = job.to_batch,
                    "aggregated proof submitted"
                );
                return Poll::Proved;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(sequencer, "aggregation poll failed: {e:#}");
            }
        }
    }

    // Per-batch work.
    let batch = match client.pick_next_batch().await {
        Ok(Some(batch)) => batch,
        Ok(None) => return Poll::Idle,
        Err(e) => {
            tracing::warn!(sequencer, "poll failed: {e:#}");
            return Poll::Idle;
        }
    };

    // VK hash filter.
    if !supported_vks.is_empty() {
        let vk_norm = normalize_vk_hash(&batch.vk_hash);
        if !supported_vks.contains(&vk_norm) {
            tracing::warn!(
                sequencer,
                batch = batch.batch_number,
                vk_hash = %batch.vk_hash,
                "unsupported VK hash, skipping"
            );
            tokio::time::sleep(Duration::from_secs(10)).await;
            return Poll::Retry;
        }
    }

    tracing::info!(
        sequencer,
        batch = batch.batch_number,
        data_bytes = batch.zisk_data.len(),
        vk_hash = %batch.vk_hash,
        "picked ZiSK batch"
    );

    // Prove. Uses tokio::process internally, so cancellation is instant.
    if aggregation {
        // Aggregated mode: keep the vadcop_final proof (no PLONK wrap) and
        // submit the stream; its publics travel inside it.
        let stream = match prover
            .generate_vadcop_proof(&batch.zisk_data, batch.batch_number, cancel)
            .await
        {
            Ok(Some(stream)) => stream,
            Ok(None) => {
                tracing::info!("proof cancelled, exiting");
                return Poll::Cancelled;
            }
            Err(e) => {
                tracing::warn!(
                    sequencer,
                    batch = batch.batch_number,
                    "proof generation failed, will retry: {e:#}"
                );
                return Poll::Retry;
            }
        };
        tracing::info!(
            batch = batch.batch_number,
            stream_bytes = stream.len(),
            "vadcop_final proof generated"
        );
        if let Err(e) = client
            .submit_zisk_proof(batch.batch_number, &stream, &[])
            .await
        {
            tracing::warn!(
                sequencer,
                batch = batch.batch_number,
                "proof submit failed, will retry: {e:#}"
            );
            return Poll::Retry;
        }
    } else {
        let result = match prover
            .generate_proof(&batch.zisk_data, batch.batch_number, cancel)
            .await
        {
            Ok(Some(result)) => result,
            Ok(None) => {
                tracing::info!("proof cancelled, exiting");
                return Poll::Cancelled;
            }
            Err(e) => {
                tracing::warn!(
                    sequencer,
                    batch = batch.batch_number,
                    "proof generation failed, will retry: {e:#}"
                );
                return Poll::Retry;
            }
        };
        tracing::info!(
            batch = batch.batch_number,
            proof_bytes = result.proof.len(),
            pv_bytes = result.public_values.len(),
            "proof generated"
        );
        if let Err(e) = client
            .submit_zisk_proof(batch.batch_number, &result.proof, &result.public_values)
            .await
        {
            tracing::warn!(
                sequencer,
                batch = batch.batch_number,
                "proof submit failed, will retry: {e:#}"
            );
            return Poll::Retry;
        }
    }
    prover.cleanup_batch_work_dir(batch.batch_number).await;
    tracing::info!(sequencer, batch = batch.batch_number, "proof submitted");
    Poll::Proved
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The flags every invocation needs besides the sequencer list. The
    /// coordinator backend keeps the proving-key flags optional.
    fn parse(sequencer_flags: &[&str]) -> Result<Args, clap::Error> {
        let mut argv = vec![
            "zksync-os-zisk-prover-service",
            "--zisk-binary",
            "/opt/zisk/bin/cargo-zisk",
            "--elf-path",
            "/app/elf/guest",
            "--coordinator-url",
            "http://127.0.0.1:7000",
        ];
        argv.extend_from_slice(sequencer_flags);
        Args::try_parse_from(argv)
    }

    #[test]
    fn sequencer_urls_accepts_a_comma_separated_list() {
        let args = parse(&["--sequencer-urls", "http://a:3124,http://user:pass@b:3124"]).unwrap();
        assert_eq!(
            args.sequencer_urls,
            vec!["http://a:3124", "http://user:pass@b:3124"]
        );
    }

    #[test]
    fn sequencer_urls_accepts_the_flag_repeated() {
        let args = parse(&[
            "--sequencer-urls",
            "http://a:3124",
            "--sequencer-urls",
            "http://b:3124",
        ])
        .unwrap();
        assert_eq!(args.sequencer_urls, vec!["http://a:3124", "http://b:3124"]);
    }

    #[test]
    fn the_old_singular_flag_still_works() {
        let args = parse(&["--sequencer-url", "http://a:3124"]).unwrap();
        assert_eq!(args.sequencer_urls, vec!["http://a:3124"]);
    }

    #[test]
    fn a_sequencer_is_required() {
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn sleeps_only_after_every_sequencer_came_back_idle() {
        let mut cycle = IdleCycle::new(2);
        assert!(!cycle.record(Poll::Idle), "first idle of two: keep going");
        assert!(cycle.record(Poll::Idle), "both idle: sleep");
        assert!(
            !cycle.record(Poll::Idle),
            "a new cycle starts after sleeping"
        );
        assert!(!cycle.record(Poll::Proved), "work resets the streak");
        assert!(
            !cycle.record(Poll::Idle),
            "the streak restarted after the proof"
        );
        assert!(cycle.record(Poll::Idle));
    }

    #[test]
    fn a_single_sequencer_sleeps_on_every_idle_poll() {
        let mut cycle = IdleCycle::new(1);
        assert!(cycle.record(Poll::Idle));
        assert!(cycle.record(Poll::Idle));
    }

    #[test]
    fn a_retry_neither_sleeps_nor_counts_as_idle() {
        let mut cycle = IdleCycle::new(2);
        assert!(!cycle.record(Poll::Idle));
        assert!(!cycle.record(Poll::Retry), "retry right away, as before");
        assert!(cycle.record(Poll::Idle), "the earlier idle still counts");
    }
}
