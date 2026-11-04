//! ZiSK proof generation through the `cargo-zisk` command-line tool.
//!
//! Two backends share one pipeline, selected by [`ProvingBackend`]:
//! - [`ProvingBackend::Spawn`] runs one `cargo-zisk` process per proof. The
//!   process loads the proving keys and initializes the GPU on every
//!   invocation.
//! - [`ProvingBackend::Coordinator`] (the deployed mode) shells
//!   `cargo-zisk remote` subcommands against a resident `zisk-coordinator`,
//!   whose `zisk-worker` keeps the keys and the GPU loaded for the service
//!   lifetime. The same `cargo-zisk` binary from the pinned toolchain
//!   tarball serves both backends; nothing is built from source.
//!
//! Startup runs a one-time setup per guest ELF. It must run before the first
//! proof for that ELF.
//!
//! Three proving flows share the pipeline:
//! - [`ZiskProver::generate_proof`] — per-batch STF proof with the pilfflonk
//!   wrap (`--pilfflonk`), for the server's per-batch mode.
//! - [`ZiskProver::generate_vadcop_proof`] — per-batch STF proof WITHOUT
//!   the wrap: the `vadcop_final` proof stream is kept and submitted so
//!   the aggregator guest can verify it in-zkVM (aggregated mode).
//! - [`ZiskProver::generate_aggregated_proof`] — the aggregator guest over
//!   N per-batch streams, with the pilfflonk wrap: one range proof for L1.
//!
//! Each `cargo-zisk` call runs as a subprocess via `tokio::process`. A
//! `CancellationToken` cancels the wait instantly, so shutdown does not
//! busy-poll. A failed call is logged and retried by the run loop; it does
//! not kill the daemon.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use crate::metrics::{Job, ZISK_PROVER_METRICS};

/// A pilfflonk proof is the on-chain verifier's `bytes32[69]` calldata.
const ZISK_SNARK_PROOF_BYTES: usize = 69 * 32;
// programVK(32, u64 big-endian) + guest publics(512: ziskos's full 64-word
// output region at full u64 width, 8 little-endian bytes per word, the
// guest's 8 commitment words first and zeros after) + vadcopVK(32, u64
// big-endian). This is the preimage of the SNARK's single public signal,
// built exactly like zisk-common's `snark_publics_hash`.
const ZISK_PUBLIC_VALUES_BYTES: usize = 576;
/// u64 words in ziskos's guest output region.
const ZISK_PUBLICS_WORDS: usize = 64;
/// Hash family of this lane's proving key. The aggregator guest accepts only
/// streams tagged with this family (`agg::EXPECTED_HASH_TAG`), and L1 verifies
/// only this family's pilfflonk SNARK.
const ZISK_PROOF_HASH_MODE: ZiskHashMode = ZiskHashMode::Poseidon1;
/// Number of u64 words in the guest-ELF ROM root (program VK) and in the
/// vadcop-final verification key.
const PROGRAM_VK_LEN: usize = 4;
/// Leads a SNARK proof file. A `vadcop_final` file is the flat stream, whose
/// first word is the 0/1 minimal flag, so it never starts with this.
const SNARK_FILE_MAGIC: &[u8; 8] = b"ZISKPLNK";
/// `[seed(4)][b"ZISKSEED"]`, appended to a `vadcop_final` file whose proof
/// carries the execution's random seed. The aggregator guest refuses it.
const SEED_TRAILER_TAG: u64 = u64::from_le_bytes(*b"ZISKSEED");
const SEED_TRAILER_WORDS: usize = 4 + 1;
/// How long a cancelled `cargo-zisk` gets to act on SIGINT before it is
/// killed. A remote prove spends it cancelling its coordinator job, which
/// would otherwise keep the worker's GPU busy after the daemon gave up on it.
const CANCEL_GRACE: Duration = Duration::from_secs(20);

#[derive(Debug)]
pub struct ZiskSnarkOutput {
    pub proof: Vec<u8>,
    pub public_values: Vec<u8>,
}

/// Where `cargo-zisk` does the proving work.
#[derive(Debug)]
pub enum ProvingBackend {
    /// One `cargo-zisk` process per proof, on this machine.
    Spawn(SpawnBackend),
    /// Shells `cargo-zisk remote` against the `zisk-coordinator` at this
    /// gRPC URL. The coordinator's worker holds the proving keys resident,
    /// so no per-proof key load happens. A failed remote prove re-runs the
    /// program setup once and retries: the coordinator keeps setups in
    /// memory, so a coordinator restart otherwise leaves every prove failing
    /// until this daemon restarts.
    Coordinator { url: String },
}

/// Settings for the [`ProvingBackend::Spawn`] backend. Each process needs the
/// key paths and the hardware choices, because nothing stays resident between
/// proofs.
#[derive(Debug)]
pub struct SpawnBackend {
    pub proving_key: PathBuf,
    pub proving_key_snark: PathBuf,
    pub gpu: bool,
    /// Select the ASM emulator for witness generation. It is faster than the
    /// standard emulator, but it needs a high memlock limit that containers
    /// frequently do not give.
    pub asm_emulator: bool,
}

pub struct ZiskProver {
    binary: PathBuf,
    elf_path: PathBuf,
    /// The aggregator guest ELF (aggregated mode only).
    aggregator_elf_path: Option<PathBuf>,
    backend: ProvingBackend,
    work_dir_base: PathBuf,
}

impl ZiskProver {
    pub fn new(
        binary: PathBuf,
        elf_path: PathBuf,
        aggregator_elf_path: Option<PathBuf>,
        backend: ProvingBackend,
        work_dir_base: PathBuf,
    ) -> Self {
        Self {
            binary,
            elf_path,
            aggregator_elf_path,
            backend,
            work_dir_base,
        }
    }

    fn aggregator_elf(&self) -> anyhow::Result<&Path> {
        self.aggregator_elf_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("no aggregator ELF configured (--aggregator-elf)"))
    }

    /// Work dir for a per-batch proving run (per-batch and vadcop flows).
    fn batch_work_dir(&self, batch_number: u64) -> PathBuf {
        self.work_dir_base.join(format!("batch_{batch_number}"))
    }

    /// Work dir for an aggregation-range proving run.
    fn range_work_dir(&self, from_batch: u64, to_batch: u64) -> PathBuf {
        self.work_dir_base
            .join(format!("range_{from_batch}_{to_batch}"))
    }

    /// Remove a per-batch run's work dir. The run loop calls this only after
    /// the proof has been submitted, so the artifacts survive a submit
    /// failure for a retry/diagnosis.
    pub async fn cleanup_batch_work_dir(&self, batch_number: u64) {
        let _ = tokio::fs::remove_dir_all(self.batch_work_dir(batch_number)).await;
    }

    /// Remove an aggregation-range run's work dir (after submit; see
    /// [`Self::cleanup_batch_work_dir`]).
    pub async fn cleanup_range_work_dir(&self, from_batch: u64, to_batch: u64) {
        let _ = tokio::fs::remove_dir_all(self.range_work_dir(from_batch, to_batch)).await;
    }

    /// One-time ROM setup for the STF guest ELF. Must run before the first
    /// proof for a given guest ELF; subsequent runs are cheap. Returns
    /// `Ok(false)` if cancelled.
    pub async fn ensure_program_setup(&self, cancel: &CancellationToken) -> anyhow::Result<bool> {
        let elf = self.elf_path.clone();
        self.program_setup(&elf, cancel).await
    }

    /// One-time ROM setup for the aggregator guest ELF (aggregated mode).
    /// See [`Self::ensure_program_setup`].
    pub async fn ensure_aggregator_program_setup(
        &self,
        cancel: &CancellationToken,
    ) -> anyhow::Result<bool> {
        let elf = self.aggregator_elf()?.to_path_buf();
        self.program_setup(&elf, cancel).await
    }

    async fn program_setup(&self, elf: &Path, cancel: &CancellationToken) -> anyhow::Result<bool> {
        let args = setup_args(&self.backend, elf);
        tracing::info!(elf = %elf.display(), "running program-setup");
        let start = Instant::now();
        let done = run_cancellable(&self.binary, &args, cancel).await?;
        if done {
            ZISK_PROVER_METRICS
                .program_setup_time
                .observe(start.elapsed());
            tracing::info!(
                elapsed_secs = start.elapsed().as_secs(),
                "program-setup complete"
            );
        }
        Ok(done)
    }

    /// Generate a per-batch ZiSK SNARK proof (pilfflonk wrap). Returns
    /// `Ok(None)` if cancelled.
    ///
    /// This is an async function — subprocesses are managed with `tokio::process`
    /// and cancellation uses `select!` against the token (instant response).
    pub async fn generate_proof(
        &self,
        zisk_bincode: &[u8],
        batch_number: u64,
        cancel: &CancellationToken,
    ) -> anyhow::Result<Option<ZiskSnarkOutput>> {
        let start = Instant::now();
        let work_dir = self.batch_work_dir(batch_number);
        let _ = tokio::fs::remove_dir_all(&work_dir).await;
        tokio::fs::create_dir_all(&work_dir).await?;

        let result = async {
            let input_path = work_dir.join("input.bin");
            write_zisk_input(&input_path, zisk_bincode)?;
            let proof_path = work_dir.join("proof.bin");
            tracing::info!(batch_number, "proving (STARK + pilfflonk wrap) starting");
            if !self
                .run_prove(
                    Job::Batch,
                    &self.elf_path,
                    &input_path,
                    &proof_path,
                    true,
                    cancel,
                )
                .await?
            {
                return Ok(None);
            }
            parse_proof_file(&proof_path).map(Some)
        }
        .await;

        self.finish_run(
            Job::Batch,
            &format!("batch {batch_number}"),
            &work_dir,
            start,
            result,
        )
        .await
    }

    /// Generate a per-batch `vadcop_final` proof stream (no SNARK wrap) —
    /// the per-batch flow of AGGREGATED mode. The returned bytes are the
    /// exact `get_proof_bytes()` stream the aggregator guest verifies.
    /// Returns `Ok(None)` if cancelled.
    pub async fn generate_vadcop_proof(
        &self,
        zisk_bincode: &[u8],
        batch_number: u64,
        cancel: &CancellationToken,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let start = Instant::now();
        let work_dir = self.batch_work_dir(batch_number);
        let _ = tokio::fs::remove_dir_all(&work_dir).await;
        tokio::fs::create_dir_all(&work_dir).await?;

        let result = async {
            let input_path = work_dir.join("input.bin");
            write_zisk_input(&input_path, zisk_bincode)?;
            let proof_path = work_dir.join("proof.bin");
            tracing::info!(batch_number, "proving (STARK, vadcop_final kept) starting");
            if !self
                .run_prove(
                    Job::Batch,
                    &self.elf_path,
                    &input_path,
                    &proof_path,
                    false,
                    cancel,
                )
                .await?
            {
                return Ok(None);
            }
            vadcop_stream_from_proof_file(&proof_path).map(Some)
        }
        .await;

        self.finish_run(
            Job::Batch,
            &format!("batch {batch_number}"),
            &work_dir,
            start,
            result,
        )
        .await
    }

    /// Prove an aggregation range: verify the N per-batch `vadcop_final`
    /// streams in the aggregator guest and wrap the result in a pilfflonk
    /// SNARK for L1. `streams` must be in batch order; they are validated and
    /// framed by the input assembler before proving. Returns `Ok(None)` if
    /// cancelled.
    pub async fn generate_aggregated_proof(
        &self,
        streams: &[Vec<u8>],
        from_batch: u64,
        to_batch: u64,
        cancel: &CancellationToken,
    ) -> anyhow::Result<Option<ZiskSnarkOutput>> {
        let aggregator_elf = self.aggregator_elf()?.to_path_buf();
        let input = crate::aggregator_input::assemble(streams)?;

        let start = Instant::now();
        let work_dir = self.range_work_dir(from_batch, to_batch);
        let _ = tokio::fs::remove_dir_all(&work_dir).await;
        tokio::fs::create_dir_all(&work_dir).await?;

        let result = async {
            // The assembled input is already ziskos-framed (count frame +
            // one frame per stream) — written raw, unlike the per-batch
            // bincode which gets its single frame from `write_zisk_input`.
            let input_path = work_dir.join("input.bin");
            std::fs::write(&input_path, &input)?;
            let proof_path = work_dir.join("proof.bin");
            tracing::info!(
                from_batch,
                to_batch,
                proofs = streams.len(),
                "proving aggregation range (in-zkVM verification + pilfflonk wrap) starting"
            );
            if !self
                .run_prove(
                    Job::Range,
                    &aggregator_elf,
                    &input_path,
                    &proof_path,
                    true,
                    cancel,
                )
                .await?
            {
                return Ok(None);
            }
            parse_proof_file(&proof_path).map(Some)
        }
        .await;

        self.finish_run(
            Job::Range,
            &format!("range {from_batch}..{to_batch}"),
            &work_dir,
            start,
            result,
        )
        .await
    }

    /// Shared prove invocation. The `snark` flag adds the BN254 pilfflonk
    /// wrap (`--pilfflonk`); without it the run keeps the `vadcop_final`
    /// proof. Returns `Ok(false)` if cancelled.
    async fn run_prove(
        &self,
        job: Job,
        elf: &Path,
        input_path: &Path,
        proof_path: &Path,
        snark: bool,
        cancel: &CancellationToken,
    ) -> anyhow::Result<bool> {
        let args = prove_args(&self.backend, elf, input_path, proof_path, snark);
        let prove_start = Instant::now();
        let mut attempt = run_cancellable(&self.binary, &args, cancel).await;
        if let (Err(e), ProvingBackend::Coordinator { .. }) = (&attempt, &self.backend) {
            // The coordinator keeps program setups in memory. After it
            // restarts, every prove fails with a precondition error until the
            // program is set up again, and this daemon only runs setup at
            // startup. Setup is idempotent and cheap while the coordinator
            // still knows it, so re-run it and retry once before reporting
            // the failure to the run loop.
            tracing::warn!(
                elf = %elf.display(),
                "remote prove failed ({e:#}); re-running the program setup and retrying once"
            );
            if !self.program_setup(elf, cancel).await? {
                return Ok(false);
            }
            attempt = run_cancellable(&self.binary, &args, cancel).await;
        }
        if !attempt? {
            return Ok(false);
        }
        ZISK_PROVER_METRICS.prove_time[&job].observe(prove_start.elapsed());
        anyhow::ensure!(proof_path.exists(), "proof file not generated");
        Ok(true)
    }

    /// Record metrics/logs for a finished proving run. The work dir is kept
    /// on success — the run loop removes it (via `cleanup_*_work_dir`) only
    /// after the proof has been submitted, so a submit failure doesn't lose
    /// the artifacts — and kept on failure for debugging; only a cancelled
    /// run's dir is removed here.
    async fn finish_run<T>(
        &self,
        job: Job,
        label: &str,
        work_dir: &Path,
        start: Instant,
        result: anyhow::Result<Option<T>>,
    ) -> anyhow::Result<Option<T>> {
        let elapsed = start.elapsed();
        ZISK_PROVER_METRICS.proof_generation_time[&job].observe(elapsed);
        let outcome = match &result {
            Ok(Some(_)) => crate::metrics::ProofOutcome::Success,
            Ok(None) => crate::metrics::ProofOutcome::Cancelled,
            Err(_) => crate::metrics::ProofOutcome::Failure,
        };
        ZISK_PROVER_METRICS.proofs[&(job, outcome)].inc();

        match &result {
            Ok(Some(_)) => {
                // Kept until submit succeeds (removed by the run loop via
                // cleanup_*_work_dir): a submit failure must not lose the
                // artifacts.
                tracing::info!(
                    label,
                    elapsed_secs = elapsed.as_secs(),
                    path = %work_dir.display(),
                    "proof generated (work dir kept until submit)"
                );
            }
            Ok(None) => {
                tracing::info!(label, "proof cancelled by shutdown");
                let _ = tokio::fs::remove_dir_all(&work_dir).await;
            }
            Err(e) => {
                tracing::error!(
                    label, elapsed_secs = elapsed.as_secs(),
                    path = %work_dir.display(), "proof failed: {e}"
                );
            }
        }

        result
    }
}

fn p(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Build the one-time per-ELF setup argument vector. The spawn backend runs
/// `setup` against its own proving key. The coordinator backend runs
/// `cargo-zisk remote setup`, which uploads the ELF (the coordinator
/// content-addresses it) and generates its setup on the worker, so it passes
/// no key path: the keys live on the worker.
fn setup_args(backend: &ProvingBackend, elf: &Path) -> Vec<String> {
    match backend {
        ProvingBackend::Spawn(spawn) => vec![
            "setup".to_string(),
            "-e".into(),
            p(elf),
            "-k".into(),
            p(&spawn.proving_key),
        ],
        ProvingBackend::Coordinator { url } => vec![
            "remote".to_string(),
            "--coordinator".into(),
            url.clone(),
            "setup".into(),
            "-e".into(),
            p(elf),
        ],
    }
}

/// Build the prove argument vector. `snark` adds the BN254 pilfflonk wrap
/// (per-batch and aggregation-range modes); without it the run keeps the
/// `vadcop_final` proof (aggregated per-batch mode). The spawn backend also
/// passes the key paths and the hardware choices, which the coordinator
/// backend leaves to the worker.
fn prove_args(
    backend: &ProvingBackend,
    elf: &Path,
    input_path: &Path,
    proof_path: &Path,
    snark: bool,
) -> Vec<String> {
    match backend {
        ProvingBackend::Spawn(spawn) => {
            let mut args = vec![
                "prove".to_string(),
                "-e".into(),
                p(elf),
                "-i".into(),
                p(input_path),
                "-k".into(),
                p(&spawn.proving_key),
            ];
            if snark {
                args.push("-w".into());
                args.push(p(&spawn.proving_key_snark));
                args.push("--pilfflonk".into());
            }
            args.push("-y".into());
            args.push("-o".into());
            args.push(p(proof_path));
            if spawn.gpu {
                args.push("-g".into());
            }
            if spawn.asm_emulator {
                args.push("-a".into());
            }
            args
        }
        ProvingBackend::Coordinator { url } => {
            // Without `--pilfflonk` the remote run returns the vadcop_final
            // proof; `--pilfflonk` adds the BN254 wrap on the worker. The ELF
            // path identifies the program: the client hashes it and the
            // coordinator resolves the setup registered at startup. This path
            // has no verify flag, and none is wanted: the toolchain verifies a
            // pilfflonk proof by running its JavaScript verifier under `node`,
            // which the images do not carry.
            let mut args = vec![
                "remote".to_string(),
                "--coordinator".into(),
                url.clone(),
                "prove".into(),
                "-e".into(),
                p(elf),
                "-i".into(),
                p(input_path),
                "-o".into(),
                p(proof_path),
                "--timeout".into(),
                "0".into(),
            ];
            if snark {
                args.push("--pilfflonk".into());
            }
            args
        }
    }
}

fn write_zisk_input(path: &Path, bincode: &[u8]) -> anyhow::Result<()> {
    let len = bincode.len() as u64;
    let mut buf = Vec::with_capacity(8 + bincode.len() + 8);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bincode);
    let padding = (8 - ((8 + bincode.len()) % 8)) % 8;
    buf.extend(std::iter::repeat_n(0u8, padding));
    std::fs::write(path, &buf)?;
    Ok(())
}

/// Run a subprocess, cancellable via token. Uses `tokio::process` — no polling.
///
/// stdout/stderr are inherited so `cargo-zisk`'s progress and error output
/// reaches the daemon's console/logs: swallowing the subprocess output makes
/// field failures undiagnosable. Inheriting (rather than piping to capture)
/// also avoids blocking cargo-zisk's 200+ threads on pipe-buffer contention
/// during proof generation.
async fn run_cancellable(
    binary: &Path,
    args: &[String],
    cancel: &CancellationToken,
) -> anyhow::Result<bool> {
    let mut child = tokio::process::Command::new(binary)
        .args(args)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;

    tokio::select! {
        status = child.wait() => {
            let status = status?;
            if status.success() {
                Ok(true)
            } else {
                anyhow::bail!("{} failed with exit code: {:?}", binary.display(), status.code());
            }
        }
        _ = cancel.cancelled() => {
            tracing::info!("shutdown requested, interrupting subprocess");
            interrupt(&child);
            if tokio::time::timeout(CANCEL_GRACE, child.wait()).await.is_err() {
                tracing::warn!("subprocess still running {CANCEL_GRACE:?} after SIGINT, killing it");
                child.kill().await.ok();
            }
            Ok(false)
        }
    }
}

/// Send SIGINT, which `cargo-zisk remote` answers by cancelling its
/// coordinator job before it exits.
fn interrupt(child: &tokio::process::Child) {
    if let Some(pid) = child.id() {
        // SAFETY: `kill` has no memory-safety preconditions. `id()` is `None`
        // once the child has been reaped, so `pid` is still our child and
        // cannot have been reused by another process.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGINT) };
    }
}

// ---------------------------------------------------------------------------
// Proof-file parsing.
//
// Since ZiSK 1.4.0, `cargo-zisk prove -o <file>` writes one of two formats
// (zisk@v1.4.0-alpha `common/src/proof.rs`, `Proof::to_bytes`):
// - a `vadcop_final` proof as the flat `get_proof_bytes()` stream, plus a
//   seed trailer when the proof carries the execution's random seed;
// - a SNARK proof as `SNARK_FILE_MAGIC` followed by bincode-2 (standard
//   config) of zisk-common's `Proof { body, program_vk, random_seed }`.
//
// Rather than depending on zisk-common (which pulls in the whole proofman
// stack), the daemon mirrors the shapes it reads and deserializes with
// serde + bincode 2.
// ---------------------------------------------------------------------------

/// zisk-common's `ProofBody` variant indices, in declaration order.
const PROOF_BODY_PLONK: u32 = 1;
const PROOF_BODY_PILFFLONK: u32 = 2;

/// A SNARK file after its magic and the `ProofBody::Pilfflonk` variant index:
/// the variant's fields, then the rest of `Proof`. bincode writes an enum as
/// its variant index (a u32) followed by the variant's fields, and a struct as
/// its fields in order, so this reads the same bytes without mirroring the
/// variants the daemon never accepts.
#[cfg_attr(test, derive(serde::Serialize))]
#[derive(serde::Deserialize)]
struct ZiskPilfflonkFile {
    proof_bytes: Vec<u8>,
    // The wrap key, the u32 publics view and the seed are decoded only to
    // advance the deserializer; the wire values come from `publics_full` and
    // `rootc`.
    #[allow(dead_code)]
    vkey_json: String,
    #[allow(dead_code)]
    publics: Vec<u8>,
    publics_full: Vec<u64>,
    rootc: Vec<u64>,
    program_vk: ZiskProgramVk,
    #[allow(dead_code)]
    random_seed: Option<[u8; 32]>,
}

/// Hash family a verification key was produced under. A verification key is
/// valid only against its own family.
#[cfg_attr(test, derive(serde::Serialize))]
#[derive(serde::Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[allow(dead_code)]
enum ZiskHashMode {
    Poseidon1,
    Poseidon2,
    Blake3,
}

#[cfg_attr(test, derive(serde::Serialize))]
#[derive(serde::Deserialize)]
struct ZiskProgramVk {
    vk: Vec<u64>,
    hash_mode: ZiskHashMode,
}

/// Append `words` as big-endian u64s — the verification-key byte form.
fn extend_be(out: &mut Vec<u8>, words: &[u64]) {
    for word in words {
        out.extend_from_slice(&word.to_be_bytes());
    }
}

/// Extract `(proof, public_values)` in the server's wire format:
/// - proof: the 2,208-byte pilfflonk SNARK.
/// - public_values (576 bytes): `program_vk (32B, u64 BE) ‖ guest publics
///   (512B, 64 words of 8 LE bytes) ‖ rootCVadcopFinal (32B, u64 BE)` — the
///   exact preimage of the circuit's single public signal
///   (`sha256(...) % r`), matching zisk-common's `snark_publics_hash` and the
///   on-chain `ZiskVerifier` digest reconstruction.
///
/// `rootc` is the verification key STAMPED into the proof, which is the
/// vadcop-final key for a plain proof and a recurser key for a folded one.
/// It is read from the file rather than derived, because the two differ.
pub fn parse_proof_file(path: &Path) -> anyhow::Result<ZiskSnarkOutput> {
    let data = std::fs::read(path)?;
    let Some(rest) = data.strip_prefix(SNARK_FILE_MAGIC) else {
        anyhow::bail!(
            "proof file holds a vadcop_final proof, expected a pilfflonk SNARK (missing --pilfflonk?)"
        );
    };
    let config = bincode::config::standard();
    let (variant, head): (u32, usize) = bincode::serde::decode_from_slice(rest, config)
        .map_err(|e| anyhow::anyhow!("failed to decode proof file: {e}"))?;
    match variant {
        PROOF_BODY_PILFFLONK => {}
        PROOF_BODY_PLONK => {
            anyhow::bail!(
                "proof file holds a PLONK SNARK, expected pilfflonk (--plonk instead of --pilfflonk?)"
            )
        }
        other => anyhow::bail!("proof file holds proof body variant {other}, expected pilfflonk"),
    }
    let rest = &rest[head..];
    let (file, consumed): (ZiskPilfflonkFile, usize) =
        bincode::serde::decode_from_slice(rest, config)
            .map_err(|e| anyhow::anyhow!("failed to decode proof file: {e}"))?;
    anyhow::ensure!(
        consumed == rest.len(),
        "trailing bytes in proof file: decoded {consumed} of {}",
        rest.len()
    );

    anyhow::ensure!(
        file.program_vk.hash_mode == ZISK_PROOF_HASH_MODE,
        "proof is of hash family {:?}, expected {ZISK_PROOF_HASH_MODE:?}",
        file.program_vk.hash_mode
    );
    anyhow::ensure!(
        file.proof_bytes.len() == ZISK_SNARK_PROOF_BYTES,
        "proof length {} != {ZISK_SNARK_PROOF_BYTES}",
        file.proof_bytes.len()
    );
    anyhow::ensure!(
        file.program_vk.vk.len() == PROGRAM_VK_LEN,
        "program VK has {} words, expected {PROGRAM_VK_LEN}",
        file.program_vk.vk.len()
    );
    anyhow::ensure!(
        file.rootc.len() == PROGRAM_VK_LEN,
        "rootC has {} words, expected {PROGRAM_VK_LEN}",
        file.rootc.len()
    );
    // ZiSK saves the flag-free `[program VK | inputs]` view; the recursion
    // layer's leaf flag is not part of the digest.
    anyhow::ensure!(
        file.publics_full.len() == PROGRAM_VK_LEN + ZISK_PUBLICS_WORDS,
        "publics_full has {} words, expected {}",
        file.publics_full.len(),
        PROGRAM_VK_LEN + ZISK_PUBLICS_WORDS
    );
    anyhow::ensure!(
        file.publics_full[..PROGRAM_VK_LEN] == file.program_vk.vk,
        "publics_full program VK differs from the proof file's program VK"
    );

    let mut public_values = Vec::with_capacity(ZISK_PUBLIC_VALUES_BYTES);
    extend_be(&mut public_values, &file.program_vk.vk);
    for word in &file.publics_full[PROGRAM_VK_LEN..] {
        public_values.extend_from_slice(&word.to_le_bytes());
    }
    extend_be(&mut public_values, &file.rootc);
    anyhow::ensure!(
        public_values.len() == ZISK_PUBLIC_VALUES_BYTES,
        "public values length {} != {ZISK_PUBLIC_VALUES_BYTES}",
        public_values.len(),
    );

    Ok(ZiskSnarkOutput {
        proof: file.proof_bytes,
        public_values,
    })
}

/// Extract the serialized `vadcop_final` proof stream — the exact byte
/// layout of `zisk_common::Proof::get_proof_bytes()`, which is what the
/// aggregator guest verifies in-zkVM — from a `cargo-zisk prove` output
/// file of a run WITHOUT `--pilfflonk` (with it, the file holds only the
/// BN254 wrap and the vadcop_final proof is gone). The file is the stream,
/// plus the seed trailer, which is cut off here; a raw stream without a
/// trailer is accepted as is.
///
/// Stream layout (u64 LE words):
/// `[minimal=0][n_publics=69][is_vadcop_final_proof=1][program_vk(4)]
/// [publics(64)][body][vadcop_vk(4)][hash_tag=0]`.
pub fn vadcop_stream_from_proof_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    use zksync_os_zisk_guest_aggregator as agg;

    let mut data = std::fs::read(path)?;
    anyhow::ensure!(
        !data.starts_with(SNARK_FILE_MAGIC),
        "proof file holds a SNARK proof, expected a vadcop_final stream \
         (run cargo-zisk prove WITHOUT --pilfflonk to keep the vadcop_final proof)"
    );
    // The stream ends with the hash tag, never with the trailer's tag, so a
    // trailing tag word can only be a trailer.
    let trailer_bytes = SEED_TRAILER_WORDS * 8;
    if data.len() >= trailer_bytes && data.ends_with(&SEED_TRAILER_TAG.to_le_bytes()) {
        data.truncate(data.len() - trailer_bytes);
    }
    let words = agg::words_from_bytes(&data).map_err(|e| anyhow::anyhow!("{e}"))?;
    agg::ProofFrame::parse(words).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hash family of this lane's proving key, as ZiSK's verifier crate
    /// names it.
    const ZISK_PROOF_HASH_FAMILY: &str = "Poseidon1";

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zisk_prover_{name}_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A SNARK file as `cargo-zisk` writes it: the magic, then the bincode
    /// `Proof` whose body is variant `variant`.
    fn snark_file(variant: u32, file: &ZiskPilfflonkFile) -> Vec<u8> {
        let config = bincode::config::standard();
        let mut bytes = SNARK_FILE_MAGIC.to_vec();
        bytes.extend(bincode::serde::encode_to_vec(variant, config).unwrap());
        bytes.extend(bincode::serde::encode_to_vec(file, config).unwrap());
        bytes
    }

    fn pilfflonk_file(program_vk: &[u64], rootc: &[u64]) -> ZiskPilfflonkFile {
        let mut publics_full = program_vk.to_vec();
        publics_full.extend(std::iter::repeat_n(
            0x4242_4242_4242_4242u64,
            ZISK_PUBLICS_WORDS,
        ));
        ZiskPilfflonkFile {
            proof_bytes: vec![7u8; ZISK_SNARK_PROOF_BYTES],
            vkey_json: r#"{"protocol":"pilfflonk"}"#.into(),
            publics: vec![0u8; 256],
            publics_full,
            rootc: rootc.to_vec(),
            program_vk: ZiskProgramVk {
                vk: program_vk.to_vec(),
                hash_mode: ZiskHashMode::Poseidon1,
            },
            random_seed: Some([9u8; 32]),
        }
    }

    /// `ZiskPilfflonkFile` reads a `Pilfflonk` body without mirroring the
    /// other variants, which relies on bincode writing a variant as its
    /// index followed by its fields.
    #[test]
    fn bincode_writes_a_variant_as_its_index_then_its_fields() {
        #[derive(serde::Serialize)]
        #[allow(dead_code)]
        enum Body {
            A(u8),
            B { x: Vec<u8> },
            C { x: Vec<u8>, y: String },
        }
        let config = bincode::config::standard();
        let mut expected = bincode::serde::encode_to_vec(2u32, config).unwrap();
        expected.extend(bincode::serde::encode_to_vec((vec![1u8, 2], "z"), config).unwrap());
        let body = Body::C {
            x: vec![1, 2],
            y: "z".into(),
        };
        assert_eq!(
            bincode::serde::encode_to_vec(&body, config).unwrap(),
            expected
        );
    }

    #[test]
    fn parse_proof_file_roundtrip() {
        let program_vk = [0x1111_2222_3333_4444u64; PROGRAM_VK_LEN];
        let rootc = [0xaaaa_bbbb_cccc_ddddu64; PROGRAM_VK_LEN];
        let dir = temp_dir("parse");
        let path = dir.join("proof.bin");
        std::fs::write(
            &path,
            snark_file(PROOF_BODY_PILFFLONK, &pilfflonk_file(&program_vk, &rootc)),
        )
        .unwrap();

        let out = parse_proof_file(&path).unwrap();
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(out.proof, vec![7u8; ZISK_SNARK_PROOF_BYTES]);
        assert_eq!(out.public_values.len(), ZISK_PUBLIC_VALUES_BYTES);
        // program VK big-endian first, then the guest publics little-endian,
        // then rootCVadcopFinal big-endian.
        assert_eq!(
            &out.public_values[..8],
            0x1111_2222_3333_4444u64.to_be_bytes().as_slice()
        );
        assert!(
            out.public_values[32..544]
                .as_chunks::<8>()
                .0
                .iter()
                .all(|c| *c == 0x4242_4242_4242_4242u64.to_le_bytes())
        );
        assert_eq!(
            &out.public_values[544..552],
            0xaaaa_bbbb_cccc_ddddu64.to_be_bytes().as_slice()
        );
    }

    #[test]
    fn parse_rejects_what_l1_cannot_verify() {
        let vk = [1u64; PROGRAM_VK_LEN];
        let dir = temp_dir("parse_reject");
        let path = dir.join("proof.bin");
        let err = |bytes: Vec<u8>| {
            std::fs::write(&path, bytes).unwrap();
            parse_proof_file(&path).unwrap_err().to_string()
        };

        // A vadcop_final stream: the run had no wrap.
        let e = err(crate::aggregator_input::synthetic_stream(0));
        assert!(e.contains("--pilfflonk"), "unexpected error: {e}");

        // A PLONK body (variant 1).
        let e = err(snark_file(PROOF_BODY_PLONK, &pilfflonk_file(&vk, &vk)));
        assert!(e.contains("PLONK"), "unexpected error: {e}");

        // A pilfflonk proof of another hash family: L1 holds the Poseidon1 key.
        let mut blake3 = pilfflonk_file(&vk, &vk);
        blake3.program_vk.hash_mode = ZiskHashMode::Blake3;
        let e = err(snark_file(PROOF_BODY_PILFFLONK, &blake3));
        assert!(e.contains("Blake3"), "unexpected error: {e}");

        // Publics that still carry the recursion layer's leaf flag.
        let mut flagged = pilfflonk_file(&vk, &vk);
        flagged.publics_full.insert(0, 1);
        let e = err(snark_file(PROOF_BODY_PILFFLONK, &flagged));
        assert!(e.contains("publics_full"), "unexpected error: {e}");

        // Trailing bytes.
        let mut long = snark_file(PROOF_BODY_PILFFLONK, &pilfflonk_file(&vk, &vk));
        long.push(0);
        let e = err(long);
        assert!(e.contains("trailing"), "unexpected error: {e}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn vadcop_stream_strips_the_seed_trailer() {
        use zksync_os_zisk_guest_aggregator as agg;

        let stream = crate::aggregator_input::synthetic_stream(3);
        let mut file = stream.clone();
        for word in [11u64, 12, 13, 14, SEED_TRAILER_TAG] {
            file.extend_from_slice(&word.to_le_bytes());
        }
        let dir = temp_dir("vadcop_stream");
        let path = dir.join("vadcop_final_proof.bin");

        std::fs::write(&path, &file).unwrap();
        assert_eq!(vadcop_stream_from_proof_file(&path).unwrap(), stream);
        // A raw stream, as an operator may hand to `aggregator_input`.
        std::fs::write(&path, &stream).unwrap();
        assert_eq!(vadcop_stream_from_proof_file(&path).unwrap(), stream);
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(stream.len(), agg::PROOF_STREAM_BYTES);
    }

    #[test]
    fn vadcop_stream_rejects_snark_and_minimal() {
        use zksync_os_zisk_guest_aggregator as agg;

        let dir = temp_dir("vadcop_reject");
        let path = dir.join("proof.bin");

        // A SNARK file — the file the daemon submits in per-batch mode.
        let vk = [0u64; PROGRAM_VK_LEN];
        std::fs::write(
            &path,
            snark_file(PROOF_BODY_PILFFLONK, &pilfflonk_file(&vk, &vk)),
        )
        .unwrap();
        let err = vadcop_stream_from_proof_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("SNARK"), "unexpected error: {err}");

        // A minimal (compressed) proof: refused.
        let mut minimal = crate::aggregator_input::synthetic_stream(0);
        minimal[..8].copy_from_slice(&1u64.to_le_bytes());
        std::fs::write(&path, &minimal).unwrap();
        let err = vadcop_stream_from_proof_file(&path)
            .unwrap_err()
            .to_string();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(err, agg::AggError::MinimalProof { flag: 1 }.to_string());
    }

    /// The guest-side stream constants and the daemon's file constants must
    /// match ZiSK's own verifier crate at the pinned version exactly — this
    /// is the only place the pin is checked mechanically (see
    /// `VADCOP_FINAL_BODY_WORDS` docs). The aggregator verifies through
    /// `ziskos::zisklib::verify_zisk_proof`, which selects the verifier from
    /// the stream's tag; this lane's proving key is Poseidon1.
    #[test]
    fn stream_constants_match_the_pinned_verifier() {
        use zksync_os_zisk_guest_aggregator as agg;
        assert_eq!(format!("{ZISK_PROOF_HASH_MODE:?}"), ZISK_PROOF_HASH_FAMILY);
        assert_eq!(
            zisk_verifier::proof_size(ZISK_PROOF_HASH_FAMILY, false),
            Some(zisk_verifier::ProofSize::Exact(
                agg::VADCOP_FINAL_BODY_WORDS * 8
            )),
        );
        assert_eq!(
            zisk_verifier::hash_tag(ZISK_PROOF_HASH_FAMILY),
            Some(agg::EXPECTED_HASH_TAG)
        );
        assert_eq!(
            zisk_verifier::expected_n_publics(false) as u64,
            agg::EXPECTED_N_PUBLICS
        );
        assert_eq!(zisk_verifier::HASH_TAG_LEN_WORDS, agg::HASH_TAG_WORDS);
        assert_eq!(zisk_verifier::VADCOP_VK_LEN_WORDS, agg::VADCOP_VK_WORDS);
        assert_eq!(zisk_verifier::SEED_TRAILER_TAG, SEED_TRAILER_TAG);
        assert_eq!(zisk_verifier::SEED_LEN_WORDS + 1, SEED_TRAILER_WORDS);
    }

    /// Cancelling a proof sends SIGINT and waits for the subprocess, so a
    /// remote prove can cancel its coordinator job before it exits.
    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_interrupts_the_subprocess() {
        use std::os::unix::fs::PermissionsExt;

        let base = temp_dir("interrupt");
        let ready = base.join("ready");
        let interrupted = base.join("interrupted");
        let fake = base.join("fake-cargo-zisk");
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\n\
                 trap 'touch \"{interrupted}\"; exit 130' INT\n\
                 touch \"{ready}\"\n\
                 while :; do sleep 0.05; done\n",
                interrupted = interrupted.display(),
                ready = ready.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

        let cancel = CancellationToken::new();
        let run = tokio::spawn({
            let cancel = cancel.clone();
            async move { run_cancellable(&fake, &[], &cancel).await }
        });
        while !ready.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cancel.cancel();
        let done = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("the subprocess exits on SIGINT, well inside the grace period")
            .unwrap()
            .unwrap();
        assert!(!done);
        assert!(interrupted.exists(), "the subprocess saw SIGINT");
        std::fs::remove_dir_all(&base).ok();
    }

    fn spawn_backend() -> ProvingBackend {
        ProvingBackend::Spawn(SpawnBackend {
            proving_key: PathBuf::from("/keys/provingKey"),
            proving_key_snark: PathBuf::from("/keys/provingKeySnark"),
            gpu: true,
            asm_emulator: false,
        })
    }

    fn coordinator_backend() -> ProvingBackend {
        ProvingBackend::Coordinator {
            url: "http://coord:7000".to_string(),
        }
    }

    fn test_prover(work_dir_base: PathBuf) -> ZiskProver {
        let elf = work_dir_base.join("test-elf");
        std::fs::create_dir_all(&work_dir_base).unwrap();
        std::fs::write(&elf, b"test elf bytes").unwrap();
        ZiskProver::new(
            PathBuf::from("/nonexistent-cargo-zisk"),
            elf,
            None,
            spawn_backend(),
            work_dir_base,
        )
    }

    /// The spawn backend must invoke only subcommands and flags that the
    /// pinned `cargo-zisk` accepts. `setup` runs on the CPU and writes into
    /// the ZiSK home, so it takes neither a GPU flag nor an output path.
    #[test]
    fn spawn_setup_args_run_setup() {
        let args = setup_args(&spawn_backend(), Path::new("/elf/guest"));
        assert_eq!(
            args,
            vec!["setup", "-e", "/elf/guest", "-k", "/keys/provingKey"]
        );
    }

    #[test]
    fn spawn_prove_args_per_batch_wrap_pilfflonk_on_the_emulator() {
        let args = prove_args(
            &spawn_backend(),
            Path::new("/elf/guest"),
            Path::new("/wd/input.bin"),
            Path::new("/wd/proof.bin"),
            true,
        );
        assert_eq!(
            args,
            vec![
                "prove",
                "-e",
                "/elf/guest",
                "-i",
                "/wd/input.bin",
                "-k",
                "/keys/provingKey",
                "-w",
                "/keys/provingKeySnark",
                "--pilfflonk",
                "-y",
                "-o",
                "/wd/proof.bin",
                "-g",
            ]
        );
    }

    /// The ASM emulator needs a memlock limit that containers frequently do
    /// not give, so the standard emulator is the default and the ASM
    /// emulator is opt-in.
    #[test]
    fn spawn_prove_args_select_the_asm_emulator_on_request() {
        let backend = ProvingBackend::Spawn(SpawnBackend {
            proving_key: PathBuf::from("/keys/provingKey"),
            proving_key_snark: PathBuf::from("/keys/provingKeySnark"),
            gpu: true,
            asm_emulator: true,
        });
        let args = prove_args(
            &backend,
            Path::new("/elf/guest"),
            Path::new("/wd/input.bin"),
            Path::new("/wd/proof.bin"),
            true,
        );
        assert!(args.iter().any(|a| a == "-a"));
    }

    /// Aggregated per-batch mode keeps the vadcop_final proof, so it must not
    /// pass the SNARK key or the wrap flag.
    #[test]
    fn spawn_prove_args_aggregated_omits_the_wrap() {
        let args = prove_args(
            &spawn_backend(),
            Path::new("/elf/guest"),
            Path::new("/wd/input.bin"),
            Path::new("/wd/proof.bin"),
            false,
        );
        assert!(!args.iter().any(|a| a == "--pilfflonk" || a == "-w"));
        assert!(!args.iter().any(|a| a == "/keys/provingKeySnark"));
    }

    /// The coordinator backend drives the pinned `cargo-zisk` through its
    /// `remote` subcommands, so the daemon needs no separately built client.
    #[test]
    fn coordinator_setup_args_upload_and_generate() {
        let args = setup_args(&coordinator_backend(), Path::new("/elf/guest"));
        assert_eq!(
            args,
            vec![
                "remote",
                "--coordinator",
                "http://coord:7000",
                "setup",
                "-e",
                "/elf/guest",
            ]
        );
        // The client never passes a proving-key path or a GPU flag; the worker
        // owns both.
        assert!(!args.iter().any(|a| a == "-k" || a == "-g"));
    }

    #[test]
    fn coordinator_prove_args_per_batch_wraps_pilfflonk() {
        let args = prove_args(
            &coordinator_backend(),
            Path::new("/elf/guest"),
            Path::new("/wd/input.bin"),
            Path::new("/wd/proof.bin"),
            true,
        );
        assert_eq!(
            args,
            vec![
                "remote",
                "--coordinator",
                "http://coord:7000",
                "prove",
                "-e",
                "/elf/guest",
                "-i",
                "/wd/input.bin",
                "-o",
                "/wd/proof.bin",
                "--timeout",
                "0",
                "--pilfflonk",
            ]
        );
        // No key, GPU, verify, or emulator flags reach the client. `-y` in
        // particular would make the toolchain run pilfflonk's JavaScript
        // verifier under `node`, which the images do not ship.
        assert!(!args.iter().any(|a| a == "-k"
            || a == "-w"
            || a == "-g"
            || a == "-y"
            || a == "-a"));
    }

    /// Aggregated per-batch mode keeps the vadcop_final proof on the remote
    /// path too: no wrap flag, and never the minimal (compressed) variant the
    /// aggregator guest rejects.
    #[test]
    fn coordinator_prove_args_aggregated_omits_the_wrap() {
        let args = prove_args(
            &coordinator_backend(),
            Path::new("/elf/guest"),
            Path::new("/wd/input.bin"),
            Path::new("/wd/proof.bin"),
            false,
        );
        assert!(
            !args
                .iter()
                .any(|a| a == "--pilfflonk" || a == "-c" || a == "--minimal")
        );
        assert_eq!(
            args[..4],
            ["remote", "--coordinator", "http://coord:7000", "prove"]
        );
    }

    /// A failed remote prove re-runs the setup and retries once, so a
    /// coordinator that lost its in-memory setups recovers without a daemon
    /// restart. The fake toolchain fails the first `prove`, then succeeds and
    /// writes the proof file; the call log must show the setup in between.
    #[cfg(unix)]
    #[tokio::test]
    async fn coordinator_prove_reruns_setup_and_retries_once() {
        use std::os::unix::fs::PermissionsExt;

        let base = std::env::temp_dir().join(format!(
            "zisk_remote_retry_test_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let calls = base.join("calls.log");
        let failed_once = base.join("prove-failed-once");
        let fake = base.join("fake-cargo-zisk");
        // Argument shape: `remote --coordinator URL <subcommand> ...`.
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\n\
                 echo \"$4\" >> '{calls}'\n\
                 case \"$4\" in\n\
                   setup) exit 0 ;;\n\
                   prove)\n\
                     if [ ! -e '{failed_once}' ]; then touch '{failed_once}'; exit 1; fi\n\
                     while [ $# -gt 0 ]; do\n\
                       if [ \"$1\" = -o ]; then echo proof > \"$2\"; exit 0; fi\n\
                       shift\n\
                     done\n\
                     exit 1 ;;\n\
                   *) exit 2 ;;\n\
                 esac\n",
                calls = calls.display(),
                failed_once = failed_once.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let elf = base.join("guest.elf");
        std::fs::write(&elf, b"elf").unwrap();

        let prover = ZiskProver::new(fake, elf.clone(), None, coordinator_backend(), base.clone());
        let proof_path = base.join("proof.bin");
        let done = prover
            .run_prove(
                Job::Batch,
                &elf,
                &base.join("input.bin"),
                &proof_path,
                false,
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(done);
        assert_eq!(std::fs::read_to_string(&proof_path).unwrap(), "proof\n");
        assert_eq!(
            std::fs::read_to_string(&calls).unwrap(),
            "prove\nsetup\nprove\n"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// `finish_run` must keep the work dir on success (submit hasn't run yet)
    /// and on failure (debugging), and remove it only on cancellation. The
    /// submitted run's dir is then reclaimed by `cleanup_batch_work_dir`.
    #[tokio::test]
    async fn finish_run_keeps_work_dir_until_submit() {
        let base = std::env::temp_dir().join(format!(
            "zisk_finish_run_test_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = tokio::fs::remove_dir_all(&base).await;
        let prover = test_prover(base.clone());

        // Success: kept — the proof still needs to be submitted.
        let success_dir = prover.batch_work_dir(1);
        tokio::fs::create_dir_all(&success_dir).await.unwrap();
        let ok: anyhow::Result<Option<()>> = Ok(Some(()));
        prover
            .finish_run(Job::Batch, "batch 1", &success_dir, Instant::now(), ok)
            .await
            .unwrap();
        assert!(
            success_dir.exists(),
            "work dir must survive a successful run until submit"
        );

        // Failure: kept for debugging.
        let failure_dir = prover.batch_work_dir(2);
        tokio::fs::create_dir_all(&failure_dir).await.unwrap();
        let err: anyhow::Result<Option<()>> = Err(anyhow::anyhow!("boom"));
        let _ = prover
            .finish_run(Job::Batch, "batch 2", &failure_dir, Instant::now(), err)
            .await;
        assert!(failure_dir.exists(), "work dir must survive a failed run");

        // Cancelled: removed (the daemon exits; no submit will follow).
        let cancelled_dir = prover.batch_work_dir(3);
        tokio::fs::create_dir_all(&cancelled_dir).await.unwrap();
        let cancelled: anyhow::Result<Option<()>> = Ok(None);
        prover
            .finish_run(
                Job::Batch,
                "batch 3",
                &cancelled_dir,
                Instant::now(),
                cancelled,
            )
            .await
            .unwrap();
        assert!(
            !cancelled_dir.exists(),
            "work dir must be removed on cancellation"
        );

        // After submit, the run loop reclaims the kept dir.
        prover.cleanup_batch_work_dir(1).await;
        assert!(
            !success_dir.exists(),
            "cleanup_batch_work_dir must remove the work dir post-submit"
        );

        std::fs::remove_dir_all(&base).ok();
    }
}
