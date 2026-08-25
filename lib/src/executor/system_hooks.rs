//! The interop commitment leaf system hook (`0x7004`).
//!
//! `L2InteropCommitmentTree` (`0x10012`) calls this hook on every leaf
//! insertion, and the hook records the leaf hash as an L2→L1 log so the tree is
//! reconstructible from data availability
//! (`system_hooks/src/call_hooks/interop_commitment_leaf.rs`). The log enters
//! the height-14 logs tree, which is leaf 0 of the chain batch root, so a
//! missing leaf gives a wrong batch public input.
//!
//! The hook is a pass-through recorder: the leaf hash is the whole calldata,
//! computed by the deployed `L2InteropCommitmentTree` bytecode, which the guest
//! executes under REVM.
//!
//! [`ZKsyncOsPrecompiles`] wraps the REVM fork's own provider and serves this
//! one address beside it. The log goes into the fork's journal-backed store, so
//! a frame revert discards it exactly as it discards a storage write — the rule
//! native applies through the frame snapshot of its `HistoryList`.

use revm::context::Cfg;
use revm::context_interface::ContextTr;
use revm::handler::PrecompileProvider;
use revm::interpreter::{CallInputs, Gas, InstructionResult, InterpreterResult};
use revm::primitives::{address, Address, AddressSet, B256, U256};
use zksync_os_revm::l2_to_l1_logs::L2ToL1LogStore;
use zksync_os_revm::precompiles::calldata_view::CalldataView;
use zksync_os_revm::precompiles::ZKsyncPrecompiles;
use zksync_os_revm::ZkSpecId;

/// The interop commitment leaf reporting hook.
pub const INTEROP_COMMITMENT_LEAF_HOOK_ADDRESS: Address =
    address!("0000000000000000000000000000000000007004");

/// `L2InteropCommitmentTree`, the only caller the hook accepts.
pub const L2_INTEROP_COMMITMENT_TREE_ADDRESS: Address =
    address!("0000000000000000000000000000000000010012");

/// The ZKsync OS precompile set the guest executes with: the REVM fork's own
/// provider plus the interop commitment leaf hook.
///
/// Public so host-side witness builders can run their read-discovery pass
/// through the exact same precompile set the guest uses, instead of maintaining
/// a drifting replica.
#[derive(Debug, Clone)]
pub struct ZKsyncOsPrecompiles {
    inner: ZKsyncPrecompiles,
    spec: ZkSpecId,
}

impl ZKsyncOsPrecompiles {
    pub fn new_with_spec(spec: ZkSpecId) -> Self {
        Self {
            inner: ZKsyncPrecompiles::new_with_spec(spec),
            spec,
        }
    }

    /// The hook is an AtlasV4 system contract. An older spec must reach the
    /// empty-account behaviour at that address, because a call an older native
    /// treats as a call to nothing must not emit a log there.
    fn serves_interop_commitment_leaf_hook(&self) -> bool {
        ZkSpecId::AtlasV4.is_enabled_in(self.spec)
    }
}

impl<CTX> PrecompileProvider<CTX> for ZKsyncOsPrecompiles
where
    CTX: ContextTr<Cfg: Cfg<Spec = ZkSpecId>>,
    CTX::Journal: L2ToL1LogStore,
{
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        if spec == self.spec {
            return false;
        }
        *self = Self::new_with_spec(spec);
        true
    }

    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<Self::Output>, String> {
        if self.serves_interop_commitment_leaf_hook()
            && inputs.bytecode_address == INTEROP_COMMITMENT_LEAF_HOOK_ADDRESS
        {
            return Ok(Some(interop_commitment_leaf_hook(context, inputs)));
        }
        <ZKsyncPrecompiles as PrecompileProvider<CTX>>::run(&mut self.inner, context, inputs)
    }

    /// The hook is not warmed: native charges a cold access for it, as it does
    /// for every other system hook, and warming an address changes execution.
    fn warm_addresses(&self) -> &AddressSet {
        <ZKsyncPrecompiles as PrecompileProvider<CTX>>::warm_addresses(&self.inner)
    }

    fn contains(&self, address: &Address) -> bool {
        <ZKsyncPrecompiles as PrecompileProvider<CTX>>::contains(&self.inner, address)
            || (self.serves_interop_commitment_leaf_hook()
                && *address == INTEROP_COMMITMENT_LEAF_HOOK_ADDRESS)
    }
}

/// Record an interop commitment tree leaf as an L2→L1 log, mirroring native
/// `interop_commitment_leaf_hook`.
///
/// The hook charges native resources but no EVM gas, because
/// `L2InteropCommitmentTree` charges the gas itself, so every exit returns the
/// full call gas. A caller other than that contract gets the empty-account
/// behaviour; a delegate call, a call carrying value, a static call and a
/// calldata length other than the 32-byte leaf hash all revert.
fn interop_commitment_leaf_hook<CTX>(ctx: &mut CTX, inputs: &CallInputs) -> InterpreterResult
where
    CTX: ContextTr,
    CTX::Journal: L2ToL1LogStore,
{
    let gas = Gas::new(inputs.gas_limit);
    let stop = || InterpreterResult::new(InstructionResult::Stop, [].into(), gas);
    let revert = || InterpreterResult::new(InstructionResult::Revert, [].into(), gas);

    if inputs.caller != L2_INTEROP_COMMITMENT_TREE_ADDRESS {
        return stop();
    }
    let is_delegate = inputs.bytecode_address != inputs.target_address;
    if is_delegate || inputs.value.get() != U256::ZERO || inputs.is_static {
        return revert();
    }

    let view = CalldataView::new(ctx, &inputs.input);
    let calldata = view.as_slice();
    if calldata.len() != 32 {
        return revert();
    }
    let leaf_hash = B256::from_slice(calldata);
    drop(view);

    ctx.journal_mut().push_l2_to_l1_log(
        L2_INTEROP_COMMITMENT_TREE_ADDRESS,
        B256::ZERO,
        leaf_hash,
    );
    stop()
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::database::{CacheDB, EmptyDB};
    use revm::primitives::{Bytes, TxKind};
    use revm::state::{AccountInfo, Bytecode};
    use revm::{context::TxEnv, ExecuteEvm};
    use zksync_os_revm::l2_to_l1_logs::L2ToL1Log;
    use zksync_os_revm::transaction::abstraction::ZKsyncTxBuilder;
    use zksync_os_revm::{zk_context, ZkBuilder};

    const OP_MSTORE: u8 = 0x52;
    const OP_GAS: u8 = 0x5a;
    const OP_PUSH1: u8 = 0x60;
    const OP_PUSH20: u8 = 0x73;
    const OP_PUSH32: u8 = 0x7f;
    const OP_CALL: u8 = 0xf1;
    const OP_RETURN: u8 = 0xf3;
    const OP_REVERT: u8 = 0xfd;

    const CALLER: Address = address!("0000000000000000000000000000000000000c0f");

    /// Code that stores `leaf` in memory, calls the hook with it as the whole
    /// 32-byte calldata, and then ends the frame with `terminator`.
    fn calls_the_hook(leaf: B256, terminator: u8) -> Bytes {
        let mut code = vec![OP_PUSH32];
        code.extend_from_slice(leaf.as_slice());
        code.extend_from_slice(&[OP_PUSH1, 0, OP_MSTORE]);
        code.extend_from_slice(&[
            OP_PUSH1, 0, // return data length
            OP_PUSH1, 0, // return data offset
            OP_PUSH1, 32, // argument length: the leaf hash
            OP_PUSH1, 0, // argument offset
            OP_PUSH1, 0, // call value
            OP_PUSH20,
        ]);
        code.extend_from_slice(INTEROP_COMMITMENT_LEAF_HOOK_ADDRESS.as_slice());
        code.extend_from_slice(&[OP_GAS, OP_CALL]);
        // End the frame carrying the call status as the 32-byte output.
        code.extend_from_slice(&[OP_PUSH1, 0, OP_MSTORE, OP_PUSH1, 32, OP_PUSH1, 0, terminator]);
        code.into()
    }

    /// Run one transaction that calls `code` deployed at `contract`, and report
    /// the L2→L1 logs that survived.
    fn logs_of_a_call(spec: ZkSpecId, contract: Address, code: Bytes) -> Vec<L2ToL1Log> {
        let mut database = CacheDB::new(EmptyDB::default());
        database.insert_account_info(
            CALLER,
            AccountInfo {
                balance: U256::from(1_000_000_000_000_000_000u64),
                ..Default::default()
            },
        );
        database.insert_account_info(
            contract,
            AccountInfo {
                code: Some(Bytecode::new_raw(code)),
                ..Default::default()
            },
        );

        let mut evm = zk_context(database, spec)
            .modify_cfg_chained(|cfg| cfg.spec = spec)
            .build_zk()
            .with_precompiles(ZKsyncOsPrecompiles::new_with_spec(spec));
        let transaction = ZKsyncTxBuilder::new()
            .base(
                TxEnv::builder()
                    .caller(CALLER)
                    .kind(TxKind::Call(contract))
                    .gas_limit(1_000_000)
                    .gas_price(0),
            )
            .tx_hash(B256::ZERO)
            .build()
            .expect("transaction builds");
        evm.0.ctx.journaled_state.set_tx_number(0);
        evm.transact(transaction).expect("transaction runs");
        evm.0.ctx.journaled_state.take_l2_to_l1_logs()
    }

    /// The hook records the leaf hash exactly as native's
    /// `push_interop_commitment_leaf` does: shard 0, service flag set, sender
    /// `0x10012`, key zero, value the leaf hash.
    #[test]
    fn records_the_leaf_hash_as_a_service_log() {
        let leaf = B256::repeat_byte(0xab);
        let logs = logs_of_a_call(
            ZkSpecId::AtlasV4,
            L2_INTEROP_COMMITMENT_TREE_ADDRESS,
            calls_the_hook(leaf, OP_RETURN),
        );
        assert_eq!(logs.len(), 1, "one leaf insertion emits one log");
        assert_eq!(logs[0].l2_shard_id, 0);
        assert!(logs[0].is_service);
        assert_eq!(logs[0].tx_number_in_block, 0);
        assert_eq!(logs[0].sender, L2_INTEROP_COMMITMENT_TREE_ADDRESS);
        assert_eq!(logs[0].key, B256::ZERO);
        assert_eq!(logs[0].value, leaf);
    }

    /// Only `L2InteropCommitmentTree` may report a leaf. Any other caller gets
    /// the empty-account behaviour, so no log reaches the logs tree.
    #[test]
    fn rejects_a_caller_other_than_the_commitment_tree() {
        let logs = logs_of_a_call(
            ZkSpecId::AtlasV4,
            address!("0000000000000000000000000000000000009999"),
            calls_the_hook(B256::repeat_byte(0xab), OP_RETURN),
        );
        assert!(logs.is_empty(), "an unauthorised caller emits no log");
    }

    /// A frame that reverts discards its leaf log, exactly as it discards a
    /// storage write. Native applies the same rule through the frame snapshot
    /// of its `HistoryList`.
    #[test]
    fn a_reverted_frame_discards_the_leaf_log() {
        let logs = logs_of_a_call(
            ZkSpecId::AtlasV4,
            L2_INTEROP_COMMITMENT_TREE_ADDRESS,
            calls_the_hook(B256::repeat_byte(0xab), OP_REVERT),
        );
        assert!(logs.is_empty(), "a reverted frame keeps no leaf log");
    }

    /// The hook is an AtlasV4 system contract. An older spec must see an empty
    /// account at `0x7004`, so a call there emits nothing.
    #[test]
    fn older_specs_see_an_empty_account_at_the_hook_address() {
        for spec in [ZkSpecId::AtlasV1, ZkSpecId::AtlasV2, ZkSpecId::AtlasV3] {
            let logs = logs_of_a_call(
                spec,
                L2_INTEROP_COMMITMENT_TREE_ADDRESS,
                calls_the_hook(B256::repeat_byte(0xab), OP_RETURN),
            );
            assert!(logs.is_empty(), "{spec:?} must not serve the hook");
        }
    }
}
