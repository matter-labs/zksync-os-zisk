//! ZiSK proof generation through the `cargo-zisk` command-line tool.
//!
//! Two backends share one pipeline, selected by [`ProvingBackend`]:
//! - [`ProvingBackend::Spawn`] (the default) runs one `cargo-zisk` process
//!   per proof. The process loads the proving keys and initializes the GPU
//!   on every invocation.
//! - [`ProvingBackend::Coordinator`] shells `zisk-prove-client` calls
//!   against a resident `zisk-coordinator`, whose `zisk-worker` keeps the
//!   keys and the GPU loaded for the service lifetime; the client binary
//!   ships in the ZiSK source tree.
//!
//! Startup runs a one-time setup per guest ELF. It must run before the first
//! proof for that ELF.
//!
//! Three proving flows share the pipeline:
//! - [`ZiskProver::generate_proof`] — per-batch STF proof with the PLONK
//!   wrap (`--plonk`), for the server's per-batch mode.
//! - [`ZiskProver::generate_vadcop_proof`] — per-batch STF proof WITHOUT
//!   `--plonk`: the `vadcop_final` proof stream is kept and submitted so
//!   the aggregator guest can verify it in-zkVM (aggregated mode).
//! - [`ZiskProver::generate_aggregated_proof`] — the aggregator guest over
//!   N per-batch streams, with the PLONK wrap: one range proof for L1.
//!
//! Each `cargo-zisk` call runs as a subprocess via `tokio::process`. A
//! `CancellationToken` cancels the wait instantly, so shutdown does not
//! busy-poll. A failed call is logged and retried by the run loop; it does
//! not kill the daemon.

use anyhow::Context as _;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::metrics::ZISK_PROVER_METRICS;

const ZISK_SNARK_PROOF_BYTES: usize = 768;
// programVK(32, u64 big-endian) + guest publics(512: ziskos's full 64-word
// output region at full u64 width, 8 little-endian bytes per word, the
// guest's 8 commitment words first and zeros after) + vadcopVK(32, u64
// big-endian). This is the preimage of the SNARK's single public signal,
// built exactly like zisk-common's `snark_publics_hash`.
const ZISK_PUBLIC_VALUES_BYTES: usize = 576;
/// u64 words in ziskos's guest output region.
const ZISK_PUBLICS_WORDS: usize = 64;
/// Hash family the aggregator guest can verify. `verify_zisk_proof` fixes it,
/// and its underlying `verifier()` panics on any other family, which would
/// abort inside the zkVM.
const ZISK_PROOF_HASH_FAMILY: &str = "Poseidon1";
/// Number of u64 words in the guest-ELF ROM root (program VK) and in the
/// vadcop-final verification key.
const PROGRAM_VK_LEN: usize = 4;

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
    /// Shells the toolchain's `zisk-prove-client` against the
    /// `zisk-coordinator` at this gRPC URL. The coordinator's worker holds
    /// the proving keys resident, so no per-proof key load happens.
    Coordinator { url: String },
}

/// Settings for the [`ProvingBackend::Spawn`] backend. Each process needs the
/// key paths and the hardware choices, because nothing stays resident between
/// proofs.
#[derive(Debug)]
pub struct SpawnBackend {
    pub proving_key: PathBuf,
    pub proving_key_plonk: PathBuf,
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
    /// blake3 of the guest ELF bytes. The coordinator content-addresses
    /// registered programs with this value, so the daemon derives it locally
    /// and never parses it from subprocess output.
    elf_hash_id: String,
    /// blake3 of the aggregator ELF bytes (aggregated mode only).
    aggregator_elf_hash_id: Option<String>,
}

/// blake3 of the ELF bytes: the coordinator's content address for a
/// registered program.
fn hash_elf(elf: &Path) -> anyhow::Result<String> {
    let bytes = std::fs::read(elf)
        .with_context(|| format!("read the ELF for hashing: {}", elf.display()))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

impl ZiskProver {
    pub fn new(
        binary: PathBuf,
        elf_path: PathBuf,
        aggregator_elf_path: Option<PathBuf>,
        backend: ProvingBackend,
        work_dir_base: PathBuf,
    ) -> anyhow::Result<Self> {
        let elf_hash_id = hash_elf(&elf_path)?;
        let aggregator_elf_hash_id = aggregator_elf_path.as_deref().map(hash_elf).transpose()?;
        Ok(Self {
            binary,
            elf_path,
            aggregator_elf_path,
            backend,
            work_dir_base,
            elf_hash_id,
            aggregator_elf_hash_id,
        })
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

    /// Generate a per-batch ZiSK SNARK proof (PLONK wrap). Returns
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
            tracing::info!(batch_number, "proving (STARK + PLONK wrap) starting");
            if !self
                .run_prove(&self.elf_path, &input_path, &proof_path, true, cancel)
                .await?
            {
                return Ok(None);
            }
            parse_proof_file(&proof_path).map(Some)
        }
        .await;

        self.finish_run(&format!("batch {batch_number}"), &work_dir, start, result)
            .await
    }

    /// Generate a per-batch `vadcop_final` proof stream (no PLONK wrap) —
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
                .run_prove(&self.elf_path, &input_path, &proof_path, false, cancel)
                .await?
            {
                return Ok(None);
            }
            vadcop_stream_from_proof_file(&proof_path).map(Some)
        }
        .await;

        self.finish_run(&format!("batch {batch_number}"), &work_dir, start, result)
            .await
    }

    /// Prove an aggregation range: verify the N per-batch `vadcop_final`
    /// streams in the aggregator guest and wrap the result in a PLONK SNARK
    /// for L1. `streams` must be in batch order; they are validated and
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
                "proving aggregation range (in-zkVM verification + PLONK wrap) starting"
            );
            if !self
                .run_prove(&aggregator_elf, &input_path, &proof_path, true, cancel)
                .await?
            {
                return Ok(None);
            }
            parse_proof_file(&proof_path).map(Some)
        }
        .await;

        self.finish_run(
            &format!("range {from_batch}..{to_batch}"),
            &work_dir,
            start,
            result,
        )
        .await
    }

    /// Shared prove invocation. The `plonk` flag adds the BN254 PLONK wrap
    /// (`--plonk`); without it the run keeps the `vadcop_final` proof.
    /// Returns `Ok(false)` if cancelled.
    async fn run_prove(
        &self,
        elf: &Path,
        input_path: &Path,
        proof_path: &Path,
        plonk: bool,
        cancel: &CancellationToken,
    ) -> anyhow::Result<bool> {
        let elf_hash_id = if Some(elf) == self.aggregator_elf_path.as_deref() {
            self.aggregator_elf_hash_id
                .as_deref()
                .context("the aggregator ELF is configured without its content hash")?
        } else {
            &self.elf_hash_id
        };
        let args = prove_args(
            &self.backend,
            elf,
            elf_hash_id,
            input_path,
            proof_path,
            plonk,
        );
        let prove_start = Instant::now();
        if !run_cancellable(&self.binary, &args, cancel).await? {
            return Ok(false);
        }
        ZISK_PROVER_METRICS
            .prove_time
            .observe(prove_start.elapsed());
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
        label: &str,
        work_dir: &Path,
        start: Instant,
        result: anyhow::Result<Option<T>>,
    ) -> anyhow::Result<Option<T>> {
        let elapsed = start.elapsed();
        ZISK_PROVER_METRICS.proof_generation_time.observe(elapsed);
        let outcome = match &result {
            Ok(Some(_)) => crate::metrics::ProofOutcome::Success,
            Ok(None) => crate::metrics::ProofOutcome::Cancelled,
            Err(_) => crate::metrics::ProofOutcome::Failure,
        };
        ZISK_PROVER_METRICS.proofs[&outcome].inc();

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
/// `program-setup` against its own proving key. The coordinator backend runs
/// `zisk-prove-client setup`, which uploads the content-addressed ELF and
/// generates its setup on the worker, so it passes no key path: the keys
/// live on the worker.
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
            "--coordinator".to_string(),
            url.clone(),
            "setup".into(),
            "--elf".into(),
            p(elf),
        ],
    }
}

/// Build the prove argument vector. `plonk` adds the BN254 wrap (per-batch
/// and aggregation-range modes); without it the run keeps the `vadcop_final`
/// proof (aggregated per-batch mode). The spawn backend also passes the key
/// paths and the hardware choices, which the coordinator backend leaves to
/// the worker.
fn prove_args(
    backend: &ProvingBackend,
    elf: &Path,
    elf_hash_id: &str,
    input_path: &Path,
    proof_path: &Path,
    plonk: bool,
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
            if plonk {
                args.push("-w".into());
                args.push(p(&spawn.proving_key_plonk));
                args.push("--plonk".into());
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
            // `stark` returns the vadcop_final proof stream; `plonk` adds the
            // BN254 wrap. The program is referenced by its blake3 content
            // address (`elf_hash_id`), registered at setup; the ELF path
            // stays a spawn-backend concern.
            vec![
                "--coordinator".to_string(),
                url.clone(),
                "prove".into(),
                "-H".into(),
                elf_hash_id.to_string(),
                "--input".into(),
                p(input_path),
                "--proof".into(),
                if plonk {
                    "plonk".into()
                } else {
                    "stark".to_string()
                },
                "--output".into(),
                p(proof_path),
                "--timeout".into(),
                "0".into(),
            ]
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
            tracing::info!("shutdown requested, killing subprocess");
            child.kill().await.ok();
            Ok(false)
        }
    }
}

// ---------------------------------------------------------------------------
// Proof-file parsing.
//
// `cargo-zisk prove -o <file>` writes bincode-2 (standard config) of
// zisk-common's `Proof` struct. Rather than depending on zisk-common (which
// pulls in the whole proofman stack), we mirror the exact struct shapes and
// deserialize with serde + bincode 2. Shapes must match
// zisk@v1.2.0-alpha `common/src/proof.rs` field-for-field.
//
// The encoding carries no version tag, and the 0.18 and 1.2.0 streams share a
// prefix, so an older file decodes part-way before it diverges. The daemon
// therefore selects the shape by the pinned toolchain version rather than by
// probing the bytes.
// ---------------------------------------------------------------------------

#[cfg_attr(test, derive(serde::Serialize))]
#[derive(serde::Deserialize)]
struct ZiskProofFile {
    body: ZiskProofBody,
    program_vk: ZiskProgramVk,
}

#[cfg_attr(test, derive(serde::Serialize))]
#[derive(serde::Deserialize)]
enum ZiskProofBody {
    #[allow(dead_code)]
    Vadcop {
        proof: Vec<u64>,
        zisk_vk: Vec<u64>,
        kind: ZiskVadcopKind,
        hash: String,
        publics_full: Vec<u64>,
    },
    Plonk {
        proof_bytes: Vec<u8>,
        // The wrap key and the u32 publics view are decoded only to advance
        // the deserializer; the wire values come from `publics_full` and
        // `rootc`.
        #[allow(dead_code)]
        plonk_vk: Box<ZiskPlonkVkBlob>,
        #[allow(dead_code)]
        publics: ZiskPublicValues,
        publics_full: Vec<u64>,
        rootc: Vec<u64>,
    },
}

/// Which vadcop flavor a proof carries. The variant owns the
/// `is_vadcop_final_proof` public: 1 for a leaf, 0 for a recurser fold, absent
/// for a compressed proof.
#[cfg_attr(test, derive(serde::Serialize))]
#[derive(serde::Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
enum ZiskVadcopKind {
    Final,
    Recurser,
    Minimal,
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
#[allow(dead_code)]
struct ZiskPlonkVkBlob {
    vadcop_vk: Vec<u64>,
    plonk_vkey: ZiskPlonkVkey,
}

/// snarkJS Plonk verification key (decoded only to advance the deserializer).
#[cfg_attr(test, derive(serde::Serialize))]
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct ZiskPlonkVkey {
    protocol: String,
    curve: String,
    n_public: u32,
    power: u32,
    k1: String,
    k2: String,
    qm: [String; 3],
    ql: [String; 3],
    qr: [String; 3],
    qo: [String; 3],
    qc: [String; 3],
    s1: [String; 3],
    s2: [String; 3],
    s3: [String; 3],
    x_2: [[String; 2]; 3],
    w: String,
}

/// Mirror of `PublicValues { data, #[serde(skip)] ptr }` — skipped fields are
/// absent from the bincode stream, so only `data` is mirrored.
#[cfg_attr(test, derive(serde::Serialize))]
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct ZiskPublicValues {
    data: Vec<u8>,
}

#[cfg_attr(test, derive(serde::Serialize))]
#[derive(serde::Deserialize)]
struct ZiskProgramVk {
    vk: Vec<u64>,
    #[allow(dead_code)]
    hash_mode: ZiskHashMode,
}

/// Append `words` as big-endian u64s — the verification-key byte form.
fn extend_be(out: &mut Vec<u8>, words: &[u64]) {
    for word in words {
        out.extend_from_slice(&word.to_be_bytes());
    }
}

/// Extract `(proof, public_values)` in the server's wire format:
/// - proof: the 768-byte BN254 PLONK SNARK.
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
    let (proof_file, consumed): (ZiskProofFile, usize) =
        bincode::serde::decode_from_slice(&data, bincode::config::standard())
            .map_err(|e| anyhow::anyhow!("failed to decode proof file: {e}"))?;
    anyhow::ensure!(
        consumed == data.len(),
        "trailing bytes in proof file: decoded {consumed} of {}",
        data.len()
    );

    let ZiskProofBody::Plonk {
        proof_bytes,
        publics_full,
        rootc,
        ..
    } = proof_file.body
    else {
        anyhow::bail!("proof file contains a Vadcop proof, expected Plonk (missing --plonk?)");
    };
    anyhow::ensure!(
        proof_bytes.len() == ZISK_SNARK_PROOF_BYTES,
        "proof length {} != {ZISK_SNARK_PROOF_BYTES}",
        proof_bytes.len()
    );
    anyhow::ensure!(
        proof_file.program_vk.vk.len() == PROGRAM_VK_LEN,
        "program VK has {} words, expected {PROGRAM_VK_LEN}",
        proof_file.program_vk.vk.len()
    );
    anyhow::ensure!(
        rootc.len() == PROGRAM_VK_LEN,
        "rootC has {} words, expected {PROGRAM_VK_LEN}",
        rootc.len()
    );
    // `publics_full` is the flag-free `[program VK | inputs]` view; the guest
    // publics the circuit hashes are the inputs half.
    anyhow::ensure!(
        publics_full.len() == PROGRAM_VK_LEN + ZISK_PUBLICS_WORDS,
        "publics_full has {} words, expected {}",
        publics_full.len(),
        PROGRAM_VK_LEN + ZISK_PUBLICS_WORDS
    );

    let mut public_values = Vec::with_capacity(ZISK_PUBLIC_VALUES_BYTES);
    extend_be(&mut public_values, &proof_file.program_vk.vk);
    for word in &publics_full[PROGRAM_VK_LEN..] {
        public_values.extend_from_slice(&word.to_le_bytes());
    }
    extend_be(&mut public_values, &rootc);
    anyhow::ensure!(
        public_values.len() == ZISK_PUBLIC_VALUES_BYTES,
        "public values length {} != {ZISK_PUBLIC_VALUES_BYTES}",
        public_values.len(),
    );

    Ok(ZiskSnarkOutput {
        proof: proof_bytes,
        public_values,
    })
}

/// Extract the serialized `vadcop_final` proof stream — the exact byte
/// layout of `zisk_common::Proof::get_proof_bytes()`, which is what the
/// aggregator guest verifies in-zkVM — from a `cargo-zisk prove` output
/// file with a **Vadcop** body (a run WITHOUT `--plonk`; with `--plonk`
/// the file holds only the BN254 wrap and the vadcop_final proof is gone).
///
/// Stream layout (u64 LE words):
/// `[minimal=0][n_publics=69][is_vadcop_final_proof=1][program_vk(4)]
/// [publics(64)][body][vadcop_vk(4)]`.
pub fn vadcop_stream_from_proof_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    use zksync_os_zisk_guest_aggregator as agg;

    let data = std::fs::read(path)?;
    let (proof_file, consumed): (ZiskProofFile, usize) =
        bincode::serde::decode_from_slice(&data, bincode::config::standard())
            .map_err(|e| anyhow::anyhow!("failed to decode proof file: {e}"))?;
    anyhow::ensure!(
        consumed == data.len(),
        "trailing bytes in proof file: decoded {consumed} of {}",
        data.len()
    );

    let ZiskProofBody::Vadcop {
        proof,
        zisk_vk,
        kind,
        hash,
        publics_full,
    } = proof_file.body
    else {
        anyhow::bail!(
            "proof file contains a Plonk proof, expected a vadcop_final body \
             (run cargo-zisk prove WITHOUT --plonk to keep the vadcop_final proof)"
        );
    };
    anyhow::ensure!(
        kind == ZiskVadcopKind::Final,
        "proof file carries a {kind:?} vadcop proof; the aggregator accepts \
         only a non-minimal leaf proof"
    );
    // The in-guest verifier fixes the hash family, so a proof from another
    // family would fail verification inside the zkVM with no diagnosis.
    anyhow::ensure!(
        hash == ZISK_PROOF_HASH_FAMILY,
        "proof file uses hash family {hash}, expected {ZISK_PROOF_HASH_FAMILY}"
    );
    anyhow::ensure!(
        proof.len() == agg::VADCOP_FINAL_BODY_WORDS,
        "vadcop_final body has {} words, expected {} — pil2-proofman pin mismatch?",
        proof.len(),
        agg::VADCOP_FINAL_BODY_WORDS
    );
    anyhow::ensure!(
        proof_file.program_vk.vk.len() == PROGRAM_VK_LEN,
        "program VK has {} words, expected {PROGRAM_VK_LEN}",
        proof_file.program_vk.vk.len()
    );
    anyhow::ensure!(
        zisk_vk.len() == PROGRAM_VK_LEN,
        "vadcop VK has {} words, expected {PROGRAM_VK_LEN}",
        zisk_vk.len()
    );
    // `publics_full` is the canonical flag-free `[program VK | inputs]` view
    // at full u64 width; the leaf flag lives in `kind`.
    anyhow::ensure!(
        publics_full.len() == PROGRAM_VK_LEN + agg::PUBLICS_WORDS,
        "publics_full has {} words, expected {}",
        publics_full.len(),
        PROGRAM_VK_LEN + agg::PUBLICS_WORDS
    );

    // The stream carries the program VK inside `publics_full`. The aggregator
    // reads it from there, so it must agree with the file's own field.
    anyhow::ensure!(
        publics_full[..PROGRAM_VK_LEN] == proof_file.program_vk.vk[..],
        "publics_full program VK differs from the proof file's program VK"
    );

    let mut words: Vec<u64> = Vec::with_capacity(agg::PROOF_STREAM_WORDS);
    words.push(0); // non-minimal
    words.push(agg::EXPECTED_N_PUBLICS);
    words.push(agg::IS_VADCOP_FINAL_PROOF);
    words.extend_from_slice(&publics_full);
    words.extend_from_slice(&proof);
    words.extend_from_slice(&zisk_vk);
    debug_assert_eq!(words.len(), agg::PROOF_STREAM_WORDS);

    let mut bytes = Vec::with_capacity(words.len() * 8);
    for w in &words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fe() -> String {
        "12539294771426046350380723674544937632432364684958450364901655716930754226695".into()
    }

    fn sample_vkey() -> ZiskPlonkVkey {
        ZiskPlonkVkey {
            protocol: "plonk".into(),
            curve: "bn128".into(),
            n_public: 1,
            power: 24,
            k1: "2".into(),
            k2: "3".into(),
            qm: [fe(), fe(), "1".into()],
            ql: [fe(), fe(), "1".into()],
            qr: [fe(), fe(), "1".into()],
            qo: [fe(), fe(), "1".into()],
            qc: [fe(), fe(), "1".into()],
            s1: [fe(), fe(), "1".into()],
            s2: [fe(), fe(), "1".into()],
            s3: [fe(), fe(), "1".into()],
            x_2: [[fe(), fe()], [fe(), fe()], [fe(), fe()]],
            w: fe(),
        }
    }

    #[test]
    fn parse_proof_file_roundtrip() {
        let program_vk = vec![0x1111_2222_3333_4444u64; PROGRAM_VK_LEN];
        let rootc = vec![0xaaaa_bbbb_cccc_ddddu64; PROGRAM_VK_LEN];
        let mut publics_full = program_vk.clone();
        publics_full.extend(std::iter::repeat_n(
            0x4242_4242_4242_4242u64,
            ZISK_PUBLICS_WORDS,
        ));
        let proof = ZiskProofFile {
            body: ZiskProofBody::Plonk {
                proof_bytes: vec![7u8; ZISK_SNARK_PROOF_BYTES],
                plonk_vk: Box::new(ZiskPlonkVkBlob {
                    vadcop_vk: rootc.clone(),
                    plonk_vkey: sample_vkey(),
                }),
                publics: ZiskPublicValues {
                    data: vec![0u8; 256],
                },
                publics_full: publics_full.clone(),
                rootc: rootc.clone(),
            },
            program_vk: ZiskProgramVk {
                vk: program_vk.clone(),
                hash_mode: ZiskHashMode::Poseidon1,
            },
        };

        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let dir = std::env::temp_dir().join(format!("zisk_prover_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("proof.bin");
        std::fs::write(&path, &bytes).unwrap();

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
        assert_eq!(
            &out.public_values[32..40],
            0x4242_4242_4242_4242u64.to_le_bytes().as_slice()
        );
        assert!(
            out.public_values[32..544]
                .chunks_exact(8)
                .all(|c| c == 0x4242_4242_4242_4242u64.to_le_bytes())
        );
        assert_eq!(
            &out.public_values[544..552],
            0xaaaa_bbbb_cccc_ddddu64.to_be_bytes().as_slice()
        );
    }

    #[test]
    fn vadcop_stream_extraction_roundtrip() {
        use zksync_os_zisk_guest_aggregator as agg;

        let program_vk = vec![1u64, 2, 3, 4];
        let zisk_vk = vec![5u64, 6, 7, 8];
        let body = vec![7u64; agg::VADCOP_FINAL_BODY_WORDS];
        // `[program VK | inputs]`: the first 8 input words carry 0x11111111,
        // which is the STF guest's commitment.
        let mut publics_full = program_vk.clone();
        publics_full.extend(std::iter::repeat_n(0u64, agg::PUBLICS_WORDS));
        for word in publics_full[PROGRAM_VK_LEN..PROGRAM_VK_LEN + 8].iter_mut() {
            *word = 0x1111_1111;
        }

        let proof = ZiskProofFile {
            body: ZiskProofBody::Vadcop {
                proof: body.clone(),
                zisk_vk: zisk_vk.clone(),
                kind: ZiskVadcopKind::Final,
                hash: ZISK_PROOF_HASH_FAMILY.to_string(),
                publics_full,
            },
            program_vk: ZiskProgramVk {
                vk: program_vk.clone(),
                hash_mode: ZiskHashMode::Poseidon1,
            },
        };
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let dir = std::env::temp_dir().join(format!("zisk_agg_stream_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vadcop_final_proof.bin");
        std::fs::write(&path, &bytes).unwrap();

        let stream = vadcop_stream_from_proof_file(&path).unwrap();
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(stream.len(), agg::PROOF_STREAM_BYTES);
        // Validate with the guest's own parser: the two implementations
        // must agree on the layout by construction.
        let words = agg::words_from_bytes(&stream).unwrap();
        let frame = agg::ProofFrame::parse(words).unwrap();
        assert_eq!(frame.program_vk(), program_vk.as_slice());
        assert_eq!(frame.vadcop_vk(), zisk_vk.as_slice());
        assert_eq!(frame.commitment(), [0x11u8; 32]);
        let body_start =
            agg::HEADER_WORDS + agg::LEAF_FLAG_WORDS + agg::PROGRAM_VK_WORDS + agg::PUBLICS_WORDS;
        assert_eq!(
            &words[body_start..body_start + agg::VADCOP_FINAL_BODY_WORDS],
            body.as_slice()
        );
    }

    #[test]
    fn vadcop_stream_rejects_plonk_and_minimal() {
        use zksync_os_zisk_guest_aggregator as agg;

        let dir = std::env::temp_dir().join(format!("zisk_agg_reject_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Plonk body — the file the daemon submits to the server.
        let plonk = ZiskProofFile {
            body: ZiskProofBody::Plonk {
                proof_bytes: vec![7u8; ZISK_SNARK_PROOF_BYTES],
                plonk_vk: Box::new(ZiskPlonkVkBlob {
                    vadcop_vk: vec![0; 4],
                    plonk_vkey: sample_vkey(),
                }),
                publics: ZiskPublicValues { data: vec![0; 256] },
                publics_full: vec![0u64; PROGRAM_VK_LEN + ZISK_PUBLICS_WORDS],
                rootc: vec![0; 4],
            },
            program_vk: ZiskProgramVk {
                vk: vec![0; 4],
                hash_mode: ZiskHashMode::Poseidon1,
            },
        };
        let path = dir.join("plonk.bin");
        std::fs::write(
            &path,
            bincode::serde::encode_to_vec(&plonk, bincode::config::standard()).unwrap(),
        )
        .unwrap();
        let err = vadcop_stream_from_proof_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Plonk"), "unexpected error: {err}");

        // Minimal (compressed) vadcop body: refused.
        let minimal = ZiskProofFile {
            body: ZiskProofBody::Vadcop {
                proof: vec![7u64; agg::VADCOP_FINAL_BODY_WORDS],
                zisk_vk: vec![0; 4],
                kind: ZiskVadcopKind::Minimal,
                hash: ZISK_PROOF_HASH_FAMILY.to_string(),
                publics_full: vec![0u64; PROGRAM_VK_LEN + agg::PUBLICS_WORDS],
            },
            program_vk: ZiskProgramVk {
                vk: vec![0; 4],
                hash_mode: ZiskHashMode::Poseidon1,
            },
        };
        let path = dir.join("minimal.bin");
        std::fs::write(
            &path,
            bincode::serde::encode_to_vec(&minimal, bincode::config::standard()).unwrap(),
        )
        .unwrap();
        let err = vadcop_stream_from_proof_file(&path)
            .unwrap_err()
            .to_string();
        std::fs::remove_dir_all(&dir).ok();
        assert!(err.contains("Minimal"), "unexpected error: {err}");
    }

    /// The guest-side body-size constant must match the pinned
    /// pil2-proofman verifier exactly — this is the only place the pin is
    /// checked mechanically (see `VADCOP_FINAL_BODY_WORDS` docs). The
    /// aggregator verifies through `ziskos::zisklib::verify_zisk_proof`, which
    /// fixes the hash family at Poseidon1, so the size comes from that family.
    #[test]
    fn vadcop_body_words_matches_pinned_verifier() {
        use proofman_verifier::Verifier;
        assert_eq!(
            zksync_os_zisk_guest_aggregator::VADCOP_FINAL_BODY_WORDS * 8,
            proofman_verifier::Poseidon1Verifier.expected_vadcop_final_proof_bytes(),
        );
    }

    #[test]
    fn parse_rejects_vadcop_body() {
        let proof = ZiskProofFile {
            body: ZiskProofBody::Vadcop {
                proof: vec![1, 2, 3],
                zisk_vk: vec![0; 4],
                kind: ZiskVadcopKind::Final,
                hash: ZISK_PROOF_HASH_FAMILY.to_string(),
                publics_full: vec![0u64; PROGRAM_VK_LEN + ZISK_PUBLICS_WORDS],
            },
            program_vk: ZiskProgramVk {
                vk: vec![0; 4],
                hash_mode: ZiskHashMode::Poseidon1,
            },
        };
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let dir =
            std::env::temp_dir().join(format!("zisk_prover_test_vadcop_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("proof.bin");
        std::fs::write(&path, &bytes).unwrap();
        let err = parse_proof_file(&path).unwrap_err().to_string();
        std::fs::remove_dir_all(&dir).ok();
        assert!(err.contains("Vadcop"), "unexpected error: {err}");
    }

    fn spawn_backend() -> ProvingBackend {
        ProvingBackend::Spawn(SpawnBackend {
            proving_key: PathBuf::from("/keys/provingKey"),
            proving_key_plonk: PathBuf::from("/keys/provingKeySnark"),
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
        .unwrap()
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
    fn spawn_prove_args_per_batch_wrap_plonk_on_the_emulator() {
        let args = prove_args(
            &spawn_backend(),
            Path::new("/elf/guest"),
            "unused-hash-id",
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
                "--plonk",
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
            proving_key_plonk: PathBuf::from("/keys/provingKeySnark"),
            gpu: true,
            asm_emulator: true,
        });
        let args = prove_args(
            &backend,
            Path::new("/elf/guest"),
            "unused-hash-id",
            Path::new("/wd/input.bin"),
            Path::new("/wd/proof.bin"),
            true,
        );
        assert!(args.iter().any(|a| a == "-a"));
    }

    /// Aggregated per-batch mode keeps the vadcop_final proof, so it must not
    /// pass the PLONK key or the wrap flag.
    #[test]
    fn spawn_prove_args_aggregated_omits_plonk() {
        let args = prove_args(
            &spawn_backend(),
            Path::new("/elf/guest"),
            "unused-hash-id",
            Path::new("/wd/input.bin"),
            Path::new("/wd/proof.bin"),
            false,
        );
        assert!(!args.iter().any(|a| a == "--plonk" || a == "-w"));
        assert!(!args.iter().any(|a| a == "/keys/provingKeySnark"));
    }

    #[test]
    fn coordinator_setup_args_upload_and_generate() {
        let args = setup_args(&coordinator_backend(), Path::new("/elf/guest"));
        assert_eq!(
            args,
            vec![
                "--coordinator",
                "http://coord:7000",
                "setup",
                "--elf",
                "/elf/guest",
            ]
        );
        // The client never passes a proving-key path or a GPU flag; the worker
        // owns both.
        assert!(!args.iter().any(|a| a == "-k" || a == "-g"));
    }

    #[test]
    fn coordinator_prove_args_per_batch_wraps_plonk() {
        let args = prove_args(
            &coordinator_backend(),
            Path::new("/elf/guest"),
            "0123abcd",
            Path::new("/wd/input.bin"),
            Path::new("/wd/proof.bin"),
            true,
        );
        assert_eq!(
            args,
            vec![
                "--coordinator",
                "http://coord:7000",
                "prove",
                "-H",
                "0123abcd",
                "--input",
                "/wd/input.bin",
                "--proof",
                "plonk",
                "--output",
                "/wd/proof.bin",
                "--timeout",
                "0",
            ]
        );
        // No key, GPU, verify, or emulator flags reach the client.
        assert!(!args.iter().any(|a| a == "-k"
            || a == "-w"
            || a == "-g"
            || a == "-y"
            || a == "--emulator"));
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
            .finish_run("batch 1", &success_dir, Instant::now(), ok)
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
            .finish_run("batch 2", &failure_dir, Instant::now(), err)
            .await;
        assert!(failure_dir.exists(), "work dir must survive a failed run");

        // Cancelled: removed (the daemon exits; no submit will follow).
        let cancelled_dir = prover.batch_work_dir(3);
        tokio::fs::create_dir_all(&cancelled_dir).await.unwrap();
        let cancelled: anyhow::Result<Option<()>> = Ok(None);
        prover
            .finish_run("batch 3", &cancelled_dir, Instant::now(), cancelled)
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
