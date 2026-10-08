//! Pins the fee semantics the guest executes with: on AtlasV3 and later, an L2 transaction in a
//! block with base fee 0 sees GASPRICE == 0, as native ZKsync OS does. zksync-os-revm v0.3.2
//! returned the tip, which made the seal-time ZisK commitment diverge from native on such blocks.

use revm::{
    context::TxEnv,
    database::{CacheDB, EmptyDB},
    primitives::{address, Address, Bytes, TxKind, B256, U256},
    state::{AccountInfo, Bytecode},
    ExecuteEvm,
};
use zksync_os_revm::{
    constants::BASE_TOKEN_HOLDER_ADDRESS, zk_context, ZKsyncTx, ZkBuilder, ZkSpecId,
};

const CALLER: Address = address!("0000000000000000000000000000000000100001");
const TARGET: Address = address!("0000000000000000000000000000000000100002");
const INITIAL_BALANCE: u64 = 1_000_000_000_000_000_000;
const GAS_LIMIT: u64 = 200_000;
const GAS_PRICE: u128 = 2_000_000_000;
const TIP: u128 = 1_000_000_000;
// GASPRICE PUSH1 1 ADD PUSH0 SSTORE STOP: a zero gas price still writes slot 0 (as 1).
const CODE: &[u8] = &[0x3a, 0x60, 0x01, 0x01, 0x5f, 0x55, 0x00];

/// Slot 0 of `TARGET` after one EIP-1559 call with `tip` in a block with `basefee`.
fn observed_gasprice_plus_one(spec: ZkSpecId, basefee: u64, tip: u128) -> U256 {
    let mut db = CacheDB::new(EmptyDB::default());
    for address in [CALLER, BASE_TOKEN_HOLDER_ADDRESS] {
        db.insert_account_info(
            address,
            AccountInfo {
                balance: U256::from(INITIAL_BALANCE),
                ..Default::default()
            },
        );
    }
    db.insert_account_info(
        TARGET,
        AccountInfo {
            code: Some(Bytecode::new_raw(Bytes::from_static(CODE))),
            ..Default::default()
        },
    );
    let mut evm = zk_context(db, spec)
        .modify_block_chained(|block| block.basefee = basefee)
        .build_zk();
    evm.0.ctx.journaled_state.set_tx_number(0);
    let tx = ZKsyncTx::builder()
        .base(
            TxEnv::builder()
                .caller(CALLER)
                .kind(TxKind::Call(TARGET))
                .data(Bytes::new())
                .nonce(0)
                .gas_limit(GAS_LIMIT)
                .gas_price(GAS_PRICE)
                .gas_priority_fee(Some(tip))
                .tx_type(Some(2)),
        )
        .mint(U256::from(GAS_LIMIT) * U256::from(GAS_PRICE))
        .refund_recipient(Some(CALLER))
        .tx_hash(B256::repeat_byte(0x17))
        .build_fill()
        .expect("transaction builds");
    let result = evm.transact(tx).expect("transaction executes");
    assert!(result.result.is_success(), "{:?}", result.result);
    result.state[&TARGET].storage[&U256::ZERO].present_value
}

#[test]
fn zero_base_fee_gasprice_is_zero_on_atlas_v3_and_later() {
    for spec in [ZkSpecId::AtlasV3, ZkSpecId::AtlasV4] {
        assert_eq!(
            observed_gasprice_plus_one(spec, 0, TIP),
            U256::ONE,
            "{spec:?}"
        );
    }
}

#[test]
fn nonzero_base_fee_keeps_the_effective_gasprice() {
    for spec in [ZkSpecId::AtlasV3, ZkSpecId::AtlasV4] {
        assert_eq!(
            observed_gasprice_plus_one(spec, TIP as u64, TIP),
            U256::from(2 * TIP + 1),
            "{spec:?}"
        );
    }
}
