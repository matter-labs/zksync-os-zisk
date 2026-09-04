//! Guard against a perturbed guest.
//!
//! This tool is the one place native ZKsync OS and the ZiSK guest lib resolve
//! into a single cargo graph, so the guest builds here with unified features
//! and a toolchain the shipping crates do not use. Before the tool reports any
//! verdict it replays one case from the committed EEST corpus. Reproducing the
//! committed native reference values proves this build of the guest is
//! equivalent to the shipping one on every axis a verdict rests on.

use anyhow::{bail, Context};
use sha2::{Digest, Sha256};
use zksync_os_zisk_test_utils::{build_batch_input, check_against_native, HeaderHashCheck};

use crate::report::SelfCheckReport;

/// The committed corpus shard the pinned case lives in.
const SHARD: &[u8] =
    include_bytes!("../../eest-corpus/shards/berlin_eip2929_gas_cost_increases.tar.zst");

/// The case, named by the SHA-256 of its canonical JSON, as the corpus names
/// every case.
const CASE: &str = "1321a564a42a31df4b13335275b46d9d1bc3641b5247514b971c12d81c01175b";

/// The corpus manifest, which pins the native producer the cases came from.
const MANIFEST: &str = include_str!("../../eest-corpus/manifest.json");

/// The zksync-os commit the committed corpus was generated with. A tool whose
/// rig resolves to a different commit compares against a different native
/// producer than the corpus baseline does.
pub fn corpus_native_reference_commit() -> String {
    serde_json::from_str::<serde_json::Value>(MANIFEST)
        .ok()
        .and_then(|manifest| {
            manifest
                .pointer("/native_reference/commit")
                .and_then(|commit| commit.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Replay the pinned case. An axis the guest fails to reproduce is a
/// perturbed guest, and the caller must refuse to report a verdict.
pub fn run() -> anyhow::Result<SelfCheckReport> {
    let started = std::time::Instant::now();
    let case_json = pinned_case()?;
    let bundle = serde_json::from_slice(&case_json).context("failed to parse the corpus case")?;

    let conversion = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        build_batch_input(&bundle, HeaderHashCheck::Armed)
    }))
    .map_err(|_| anyhow::anyhow!("the corpus case {CASE} did not convert to a batch input"))?;

    let check = check_against_native(&bundle, &conversion.batch_input);
    if let Some(failure) = check.first_failure() {
        bail!(
            "this build of the guest lib rejected the pinned corpus case {CASE}: {}",
            failure.message
        );
    }
    if let Some(mismatch) = check.first_mismatch() {
        bail!(
            "this build of the guest lib does not reproduce the pinned corpus case {CASE}: \
             {} is {} and the corpus pins {}",
            mismatch.axis.name(),
            mismatch.computed,
            mismatch.native
        );
    }

    Ok(SelfCheckReport::Passed {
        case: CASE.to_string(),
        axes_checked: check.events.len() - check.skipped().len(),
        duration_ms: started.elapsed().as_millis(),
    })
}

/// The pinned case's JSON, read out of the embedded shard and checked against
/// the digest the corpus names it by.
fn pinned_case() -> anyhow::Result<Vec<u8>> {
    let tar = zstd::stream::decode_all(SHARD).context("failed to decompress the corpus shard")?;
    let member = format!("{CASE}.json");
    let mut archive = tar::Archive::new(tar.as_slice());
    for entry in archive
        .entries()
        .context("failed to read the corpus shard")?
    {
        let mut entry = entry.context("failed to read a corpus shard entry")?;
        let path = entry.path().context("corpus shard entry has no path")?;
        if !path.ends_with(&member) {
            continue;
        }
        let mut json = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut json)
            .context("failed to read the corpus case")?;
        let digest = hex::encode(Sha256::digest(&json));
        if digest != CASE {
            bail!("the corpus case {CASE} hashes to {digest}");
        }
        return Ok(json);
    }
    bail!("the committed corpus shard holds no case {CASE}")
}
