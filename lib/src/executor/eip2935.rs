//! The EIP-2935 pre-block historical block hash write.
//!
//! From AtlasV4 on, every block writes its parent hash into the history
//! contract's ring buffer before it runs any transaction (zksync-os
//! `basic_bootloader/.../block_flow/eip_2935_historical_block_hash`).
//!
//! Native performs a direct storage write with formal-infinite resources; it
//! does not call into the contract's code, and a fixed block-intrinsic reserve
//! pays for it. The guest reproduces that mechanism rather than Ethereum's
//! system call, because a system call agrees with it only when the deployed
//! contract is the canonical EIP-2935 contract, and native's rule does not
//! depend on that.

use revm::database::CacheDB;
use revm::primitives::{address, Address, B256, U256};
use revm::DatabaseRef;

use super::proven_db::ProvenDB;
use crate::account_props::DELEGATED_STATUS_BYTE;

/// The EIP-2935 history contract.
pub(super) const HISTORY_STORAGE_ADDRESS: Address =
    address!("0000f90827f1c53a10cb7a02335b175320002935");

/// The number of parent hashes the history ring holds.
pub(super) const HISTORY_SERVE_WINDOW: u64 = 8191;

/// The ring slot that block `block_number` writes.
pub(super) fn history_slot(block_number: u64) -> U256 {
    U256::from((block_number - 1) % HISTORY_SERVE_WINDOW)
}

/// Write `parent_hash` into the history ring for `block_number` and return the
/// write-set entry it contributes, if any.
///
/// The write lands in the `CacheDB` overlay, so a transaction of this block that
/// reads the slot observes it, exactly as it observes native's IO write.
///
/// Native gates the whole step on `is_contract()` of the history account, which
/// is `observable_bytecode_len > 0 && !is_delegated`. The guest evaluates that
/// against the merkle-authenticated pre-state of the account, and fails closed
/// when the witness carries no proof for it: the write moves `tree_root_after`,
/// so an unauthenticated gate would let an operator add or drop a state change.
///
/// The gate reads the batch pre-state, so a batch that deploys the history
/// contract in one of its own blocks disagrees with native for the blocks that
/// follow. Such a batch fails the tree update rather than committing a wrong
/// root.
///
/// The write joins the batch write set only when it changes the slot, which is
/// the rule the guest applies to execution writes.
pub(super) fn apply_pre_block_write(
    block_number: u64,
    parent_hash: &B256,
    cache_db: &mut CacheDB<ProvenDB>,
) -> Option<((Address, U256), U256)> {
    assert!(
        block_number >= 1,
        "EIP-2935 has no ring slot for block number 0"
    );

    // Native asks the IO subsystem only for `observable_bytecode_len` and
    // `is_delegated`, and returns without writing when the account is not a
    // contract. `basic_ref` fails when the witness carries no authenticated
    // pre-state for the account, and it fails when a proof claims the account
    // exists but no preimage backs it.
    let account = cache_db
        .db
        .basic_ref(HISTORY_STORAGE_ADDRESS)
        .unwrap_or_else(|e| {
            panic!(
                "AtlasV4 block {block_number} carries no authenticated pre-state for the \
                 EIP-2935 history contract {HISTORY_STORAGE_ADDRESS}: {e}"
            )
        });
    account.as_ref()?;

    let fields = cache_db.db.pre_state_code_fields(&HISTORY_STORAGE_ADDRESS);
    let is_delegated = (fields.versioning >> 56) as u8 == DELEGATED_STATUS_BYTE;
    if fields.observable_bytecode_len == 0 || is_delegated {
        return None;
    }

    let slot = history_slot(block_number);
    let value = U256::from_be_bytes(parent_hash.0);

    let previous = cache_db
        .storage_ref(HISTORY_STORAGE_ADDRESS, slot)
        .unwrap_or_else(|e| {
            panic!(
                "AtlasV4 block {block_number} carries no authenticated pre-state for the \
                 EIP-2935 history slot {slot}: {e}"
            )
        });

    cache_db
        .insert_account_storage(HISTORY_STORAGE_ADDRESS, slot, value)
        .expect("the history contract's pre-state is authenticated above");

    (previous != value).then_some(((HISTORY_STORAGE_ADDRESS, slot), value))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The history contract address is the 160-bit value native builds from its
    /// three limbs.
    #[test]
    fn history_address_matches_native() {
        let mut expected = [0u8; 20];
        expected[0..4].copy_from_slice(&0x0000_F908u32.to_be_bytes());
        expected[4..12].copy_from_slice(&0x27F1_C53A_10CB_7A02u64.to_be_bytes());
        expected[12..20].copy_from_slice(&0x335B_1753_2000_2935u64.to_be_bytes());
        assert_eq!(HISTORY_STORAGE_ADDRESS, Address::from(expected));
    }

    /// The ring slot is `(block_number - 1) % 8191`, right-aligned in the
    /// 32-byte key, and it wraps at the window boundary.
    #[test]
    fn history_slot_wraps_at_the_serve_window() {
        assert_eq!(history_slot(1), U256::ZERO);
        assert_eq!(history_slot(2), U256::from(1u64));
        assert_eq!(history_slot(HISTORY_SERVE_WINDOW), U256::from(8190u64));
        assert_eq!(history_slot(HISTORY_SERVE_WINDOW + 1), U256::ZERO);
        assert_eq!(history_slot(HISTORY_SERVE_WINDOW + 2), U256::from(1u64));

        let key = B256::from(history_slot(HISTORY_SERVE_WINDOW).to_be_bytes::<32>());
        assert_eq!(key.as_slice()[..24], [0u8; 24]);
        assert_eq!(key.as_slice()[24..], 8190u64.to_be_bytes());
    }
}
