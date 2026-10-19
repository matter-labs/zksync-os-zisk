//! Cross-check the guest's commitments against the native reference values a
//! state dump carries.
//!
//! The guest re-derives the batch from the witness alone. Every value it
//! commits to is compared here against what native ZKsync OS produced for the
//! same block, in the order the guest derives them, so the first mismatch
//! names where the two implementations part.

use revm::primitives::B256;
use zksync_os_revm::ZkSpecId;
use zksync_os_zisk_lib::commitment::{chain_config_hash, ChainConfig, ChainConfigLayout};
use zksync_os_zisk_lib::executor;
use zksync_os_zisk_lib::types::BatchInput;

use crate::dump::{hb256, zk_spec, StateDumpBundle};

/// A value the native reference pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(untagged)]
pub enum AxisValue {
    Hash(B256),
    Count(u64),
}

impl core::fmt::Display for AxisValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AxisValue::Hash(hash) => write!(f, "{hash}"),
            AxisValue::Count(count) => write!(f, "{count}"),
        }
    }
}

/// The commitment sub-components the native reference pins, in the order the
/// guest derives them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Axis {
    TreeRootAfter,
    LeafCountAfter,
    StateBefore,
    StateAfter,
    BatchOutputHash,
    ChainConfigHash,
    BatchPublicInput,
}

impl Axis {
    pub fn name(self) -> &'static str {
        match self {
            Axis::TreeRootAfter => "tree_root_after",
            Axis::LeafCountAfter => "leaf_count_after",
            Axis::StateBefore => "state_before",
            Axis::StateAfter => "state_after",
            Axis::BatchOutputHash => "batch_output_hash",
            Axis::ChainConfigHash => "chain_config_hash",
            Axis::BatchPublicInput => "batch_public_input",
        }
    }
}

/// One axis of the guest against the native reference.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct AxisComparison {
    pub axis: Axis,
    pub computed: AxisValue,
    pub native: AxisValue,
}

impl AxisComparison {
    pub fn agrees(&self) -> bool {
        self.computed == self.native
    }
}

/// The stage of the guest that produced no values to compare.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    TreeUpdate,
    Execution,
}

/// A stage the guest could not complete. Guest asserts are its rejection
/// mechanism, so a panic here is a verdict, not a tool error.
#[derive(Clone, Debug, serde::Serialize)]
pub struct StageFailure {
    pub stage: Stage,
    pub message: String,
}

/// One step of the cross-check, in the order the guest derives it.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CheckEvent {
    /// A native reference value compared against the guest's.
    Axis(AxisComparison),
    /// Axes the bundle carries no native reference for.
    Skipped { axes: Vec<Axis> },
    /// The guest panicked before it produced that stage's axes.
    Failed(StageFailure),
}

/// The full cross-check of one batch.
#[derive(Clone, Debug, serde::Serialize)]
pub struct NativeCheck {
    pub events: Vec<CheckEvent>,
}

impl NativeCheck {
    /// The first axis the guest and native disagree on, walking the events in
    /// derivation order.
    pub fn first_mismatch(&self) -> Option<&AxisComparison> {
        self.events.iter().find_map(|event| match event {
            CheckEvent::Axis(comparison) if !comparison.agrees() => Some(comparison),
            _ => None,
        })
    }

    /// The first stage the guest could not complete.
    pub fn first_failure(&self) -> Option<&StageFailure> {
        self.events.iter().find_map(|event| match event {
            CheckEvent::Failed(failure) => Some(failure),
            _ => None,
        })
    }

    /// The axes the bundle carries no native reference for.
    pub fn skipped(&self) -> Vec<Axis> {
        self.events
            .iter()
            .filter_map(|event| match event {
                CheckEvent::Skipped { axes } => Some(axes.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// True when the guest reproduced every value the bundle pins.
    pub fn agrees(&self) -> bool {
        self.first_mismatch().is_none() && self.first_failure().is_none()
    }
}

/// Run the guest over `batch_input` and compare every value it commits to
/// against the native reference values `bundle` carries.
pub fn check_against_native(bundle: &StateDumpBundle, batch_input: &BatchInput) -> NativeCheck {
    let mut events = Vec::new();

    let tree_update = batch_input
        .batch_meta
        .tree_update
        .as_ref()
        .expect("a converted bundle always carries a tree update");
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tree_update.apply(&batch_input.batch_meta.tree_root_before)
    })) {
        Ok((root_after, count_after)) => {
            events.push(hashes(
                Axis::TreeRootAfter,
                root_after,
                hb256(&bundle.tree_root_after),
            ));
            events.push(CheckEvent::Axis(AxisComparison {
                axis: Axis::LeafCountAfter,
                computed: AxisValue::Count(count_after),
                native: AxisValue::Count(bundle.leaf_count_after),
            }));
        }
        Err(payload) => events.push(CheckEvent::Failed(StageFailure {
            stage: Stage::TreeUpdate,
            message: crate::panic_message(payload.as_ref()),
        })),
    }

    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        executor::execute_and_commit_debug(batch_input)
    })) {
        Ok((_output, public_input, state_before, state_after, batch_output)) => {
            events.push(hashes(
                Axis::StateBefore,
                state_before,
                hb256(&bundle.native_state_before),
            ));
            events.push(hashes(
                Axis::StateAfter,
                state_after,
                hb256(&bundle.native_state_after),
            ));
            // v0.3.0-line bundles cannot carry these (no native producer in
            // the forward path); state commitments + header hash + pubdata
            // remain the native ground truth there.
            if bundle.native_batch_output_hash.is_empty() {
                events.push(CheckEvent::Skipped {
                    axes: vec![
                        Axis::BatchOutputHash,
                        Axis::ChainConfigHash,
                        Axis::BatchPublicInput,
                    ],
                });
            } else {
                events.push(hashes(
                    Axis::BatchOutputHash,
                    batch_output,
                    hb256(&bundle.native_batch_output_hash),
                ));
                let layout = if ZkSpecId::AtlasV5.is_enabled_in(zk_spec(bundle.spec_id)) {
                    ChainConfigLayout::AtlasV5
                } else {
                    ChainConfigLayout::AtlasV4
                };
                let chain_config = chain_config_hash(
                    layout,
                    &ChainConfig {
                        chain_id: bundle.chain_id,
                        fri_proof_verification_enabled: bundle.chain_config_fri,
                        max_tx_gas_limit: bundle.chain_config_max_tx_gas_limit,
                        pubdata_content: bundle.chain_config_pubdata_content,
                        l1_tx_filtering_enabled: bundle.chain_config_l1_tx_filtering_enabled,
                        large_contracts_enabled: bundle.chain_config_large_contracts_enabled,
                    },
                );
                events.push(hashes(
                    Axis::ChainConfigHash,
                    chain_config,
                    hb256(&bundle.native_chain_config_hash),
                ));
                events.push(hashes(
                    Axis::BatchPublicInput,
                    public_input,
                    hb256(&bundle.native_batch_public_input),
                ));
            }
        }
        Err(payload) => events.push(CheckEvent::Failed(StageFailure {
            stage: Stage::Execution,
            message: crate::panic_message(payload.as_ref()),
        })),
    }

    NativeCheck { events }
}

fn hashes(axis: Axis, computed: B256, native: B256) -> CheckEvent {
    CheckEvent::Axis(AxisComparison {
        axis,
        computed: AxisValue::Hash(computed),
        native: AxisValue::Hash(native),
    })
}
