//! ZiSK Prover Service for ZKsync OS
//!
//! External prover that polls the ZKsync OS server for ZiSK batch data,
//! drives proof generation on a resident ZiSK prover service via `cargo-zisk
//! remote`, and submits the results back to the server for multi-proof
//! composition. A long-lived `zisk-coordinator` and its `zisk-worker` hold
//! the proving keys and the GPU. The daemon is a thin client and points at
//! the coordinator.
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
    /// Sequencer URL. Supports Basic Auth: http://user:pass@host:port
    #[arg(short, long)]
    sequencer_url: String,

    /// Path to the cargo-zisk binary.
    #[arg(long)]
    zisk_binary: PathBuf,

    /// Path to the ZiSK guest ELF binary.
    #[arg(long)]
    elf_path: PathBuf,

    /// gRPC URL of the resident `zisk-coordinator`. The daemon uploads the
    /// ELF and proves against this service; the proving keys and GPU live on
    /// its worker.
    #[arg(
        long,
        env = "ZISK_COORDINATOR_URL",
        default_value = "http://localhost:7000"
    )]
    coordinator_url: String,

    /// Aggregated mode: prove batches WITHOUT the PLONK wrap and submit
    /// their vadcop_final streams; poll /ZiSK-AGG for range jobs and prove
    /// them with the aggregator guest. The server must run with
    /// zisk_aggregation.enabled.
    #[arg(long, requires = "aggregator_elf")]
    aggregation: bool,

    /// Path to the ZiSK aggregator guest ELF (required with --aggregation).
    #[arg(long, requires = "aggregation")]
    aggregator_elf: Option<PathBuf>,

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
        sequencer_url = %args.sequencer_url,
        zisk_binary = %args.zisk_binary.display(),
        elf_path = %args.elf_path.display(),
        coordinator_url = %args.coordinator_url,
        aggregation = args.aggregation,
        aggregator_elf = ?args.aggregator_elf,
        supported_vk_hashes = ?supported_vks,
        vk_filter = if supported_vks.is_empty() { "disabled (accepts all)" } else { "enabled" },
        "Starting ZiSK prover service"
    );

    // Validate paths.
    let mut required_paths = vec![
        ("zisk_binary", &args.zisk_binary),
        ("elf_path", &args.elf_path),
    ];
    if let Some(ref aggregator_elf) = args.aggregator_elf {
        required_paths.push(("aggregator_elf", aggregator_elf));
    }
    for (name, path) in required_paths {
        anyhow::ensure!(path.exists(), "{name} does not exist: {}", path.display());
    }

    // Start Prometheus metrics server.
    let metrics_addr: std::net::SocketAddr = args.metrics_address.parse()?;
    let exporter = vise_exporter::MetricsExporter::default();
    tokio::spawn(exporter.start(metrics_addr));
    tracing::info!(address = %metrics_addr, "metrics server started");

    let client = sequencer_client::SequencerClient::new(&args.sequencer_url, &prover_id)?;
    tracing::info!(url = client.url(), "connected to sequencer");

    let prover = prover::ZiskProver::new(
        args.zisk_binary,
        args.elf_path,
        args.aggregator_elf.clone(),
        args.coordinator_url,
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

    // One-time setup for the guest ELF(s) on the prover service (upload +
    // setup, once per ELF at startup).
    if !prover.ensure_setup(&cancel).await? {
        tracing::info!("cancelled during remote setup, exiting");
        return Ok(());
    }
    if args.aggregation && !prover.ensure_aggregator_setup(&cancel).await? {
        tracing::info!("cancelled during aggregator remote setup, exiting");
        return Ok(());
    }

    loop {
        if cancel.is_cancelled() {
            tracing::info!("shutdown requested, exiting");
            break;
        }

        // Aggregated mode: range jobs first — a formed range is the last
        // missing piece of its MultiProof, so it beats new per-batch work.
        if args.aggregation {
            match client.pick_next_aggregation_job().await {
                Ok(Some(job)) => {
                    tracing::info!(
                        from = job.from_batch,
                        to = job.to_batch,
                        proofs = job.streams.len(),
                        "picked ZiSK aggregation range"
                    );
                    let streams: Vec<Vec<u8>> =
                        job.streams.into_iter().map(|(_, stream)| stream).collect();
                    // A transient proof-gen/submit failure must not kill the
                    // daemon: log + retry like the pick path above, so one bad
                    // run doesn't take down the whole ZiSK lane.
                    let result = match prover
                        .generate_aggregated_proof(&streams, job.from_batch, job.to_batch, &cancel)
                        .await
                    {
                        Ok(Some(result)) => result,
                        Ok(None) => {
                            tracing::info!("aggregated proof cancelled, exiting");
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(
                                from = job.from_batch,
                                to = job.to_batch,
                                "aggregated proof generation failed, will retry: {e:#}"
                            );
                            continue;
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
                            from = job.from_batch,
                            to = job.to_batch,
                            "aggregated proof submit failed, will retry: {e:#}"
                        );
                        continue;
                    }
                    prover
                        .cleanup_range_work_dir(job.from_batch, job.to_batch)
                        .await;
                    tracing::info!(
                        from = job.from_batch,
                        to = job.to_batch,
                        "aggregated proof submitted"
                    );

                    proofs_generated += 1;
                    if args.iterations > 0 && proofs_generated >= args.iterations {
                        tracing::info!(proofs_generated, "iteration limit reached");
                        break;
                    }
                    continue;
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("aggregation poll failed: {e:#}");
                }
            }
        }

        // Poll for per-batch work.
        let batch = match client.pick_next_batch().await {
            Ok(Some(batch)) => batch,
            Ok(None) => {
                tokio::select! {
                    _ = tokio::time::sleep(poll_interval) => {}
                    _ = cancel.cancelled() => break,
                }
                continue;
            }
            Err(e) => {
                tracing::warn!("poll failed: {e:#}");
                tokio::select! {
                    _ = tokio::time::sleep(poll_interval) => {}
                    _ = cancel.cancelled() => break,
                }
                continue;
            }
        };

        // VK hash filter.
        if !supported_vks.is_empty() {
            let vk_norm = normalize_vk_hash(&batch.vk_hash);
            if !supported_vks.contains(&vk_norm) {
                tracing::warn!(
                    batch = batch.batch_number,
                    vk_hash = %batch.vk_hash,
                    "unsupported VK hash, skipping"
                );
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        }

        tracing::info!(
            batch = batch.batch_number,
            data_bytes = batch.zisk_data.len(),
            vk_hash = %batch.vk_hash,
            "picked ZiSK batch"
        );

        // Prove. Uses tokio::process internally — cancellation is instant.
        // A transient proof-gen/submit failure must not kill the daemon: it is
        // logged and the batch retried (via `continue`), exactly like the pick
        // failures above — one bad run doesn't terminate the whole daemon.
        if args.aggregation {
            // Aggregated mode: keep the vadcop_final proof (no PLONK wrap)
            // and submit the stream; its publics travel inside it.
            let stream = match prover
                .generate_vadcop_proof(&batch.zisk_data, batch.batch_number, &cancel)
                .await
            {
                Ok(Some(stream)) => stream,
                Ok(None) => {
                    tracing::info!("proof cancelled, exiting");
                    break;
                }
                Err(e) => {
                    tracing::warn!(
                        batch = batch.batch_number,
                        "proof generation failed, will retry: {e:#}"
                    );
                    continue;
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
                    batch = batch.batch_number,
                    "proof submit failed, will retry: {e:#}"
                );
                continue;
            }
            prover.cleanup_batch_work_dir(batch.batch_number).await;
        } else {
            let result = match prover
                .generate_proof(&batch.zisk_data, batch.batch_number, &cancel)
                .await
            {
                Ok(Some(result)) => result,
                Ok(None) => {
                    tracing::info!("proof cancelled, exiting");
                    break;
                }
                Err(e) => {
                    tracing::warn!(
                        batch = batch.batch_number,
                        "proof generation failed, will retry: {e:#}"
                    );
                    continue;
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
                    batch = batch.batch_number,
                    "proof submit failed, will retry: {e:#}"
                );
                continue;
            }
            prover.cleanup_batch_work_dir(batch.batch_number).await;
        }

        tracing::info!(batch = batch.batch_number, "proof submitted");

        proofs_generated += 1;
        if args.iterations > 0 && proofs_generated >= args.iterations {
            tracing::info!(proofs_generated, "iteration limit reached");
            break;
        }
    }

    Ok(())
}
