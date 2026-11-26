//! Pins the pre-execution warming of L1 transactions the guest executes with. From ZKsync OS
//! v0.4.0 (AtlasV4) on, native reads the treasury and the refund recipient before the
//! transaction body runs, and every asset-tracker notification reads its caller, the L2 base
//! token. All three are warm when the body starts. zksync-os-revm v0.5.0 and earlier left them
//! cold, so a body that read one of them paid 2,600 gas instead of 100, which can change its
//! outcome and make the ZiSK commitment diverge from native.

use revm::{
    context::TxEnv,
    database::{CacheDB, EmptyDB},
    interpreter::gas::{COLD_ACCOUNT_ACCESS_COST, WARM_STORAGE_READ_COST},
    primitives::{address, Address, Bytes, TxKind, B256, U256},
    state::{AccountInfo, Bytecode},
    ExecuteEvm,
};
use zksync_os_revm::{
    constants::{BASE_TOKEN_HOLDER_ADDRESS, L2_BASE_TOKEN_ADDRESS},
    zk_context, ZKsyncTx, ZkBuilder, ZkSpecId,
};

const CALLER: Address = address!("0000000000000000000000000000000000100001");
const TARGET: Address = address!("0000000000000000000000000000000000100002");
const REFUND_RECIPIENT: Address = address!("0000000000000000000000000000000000100003");
const TREASURY_BALANCE: u64 = 1_000_000_000_000_000_000;
const GAS_LIMIT: u64 = 200_000;
const GAS_PRICE: u128 = 1;
const L1_PRIORITY_TX_TYPE: u8 = 0x7f;
/// Gas the probe spends besides `BALANCE`: `PUSH20` (3), `POP` (2) and the second `GAS` (2).
const PROBE_OVERHEAD: u64 = 7;

/// GAS PUSH20 <probe> BALANCE POP GAS SWAP1 SUB PUSH0 SSTORE STOP: slot 0 gets the gas spent
/// between the two `GAS` reads.
fn probe_code(probe: Address) -> Bytes {
    let mut code = vec![0x5a, 0x73];
    code.extend_from_slice(probe.as_slice());
    code.extend_from_slice(&[0x31, 0x50, 0x5a, 0x90, 0x03, 0x5f, 0x55, 0x00]);
    code.into()
}

/// What `BALANCE(probe)` costs the body of one L1 priority transaction to `TARGET`. The deposit
/// covers the prepaid fee plus one wei, so every spec notifies the asset tracker before the body.
fn balance_cost(spec: ZkSpecId, probe: Address) -> u64 {
    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(
        BASE_TOKEN_HOLDER_ADDRESS,
        AccountInfo {
            balance: U256::from(TREASURY_BALANCE),
            ..Default::default()
        },
    );
    db.insert_account_info(
        TARGET,
        AccountInfo {
            code: Some(Bytecode::new_raw(probe_code(probe))),
            ..Default::default()
        },
    );
    let mut evm = zk_context(db, spec).build_zk();
    evm.0.ctx.journaled_state.set_tx_number(0);
    let tx = ZKsyncTx::builder()
        .base(
            TxEnv::builder()
                .caller(CALLER)
                .kind(TxKind::Call(TARGET))
                .data(Bytes::new())
                .gas_limit(GAS_LIMIT)
                .gas_price(GAS_PRICE)
                .tx_type(Some(L1_PRIORITY_TX_TYPE)),
        )
        .mint(U256::from(GAS_LIMIT) * U256::from(GAS_PRICE) + U256::ONE)
        .refund_recipient(Some(REFUND_RECIPIENT))
        .tx_hash(B256::repeat_byte(0x18))
        .build_fill()
        .expect("transaction builds");
    let result = evm.transact(tx).expect("transaction executes");
    assert!(result.result.is_success(), "{:?}", result.result);
    let spent = result.state[&TARGET].storage[&U256::ZERO].present_value;
    u64::try_from(spent).expect("the probe cost fits in u64") - PROBE_OVERHEAD
}

#[test]
fn l1_body_sees_the_prewarmed_accounts_warm_from_atlas_v4() {
    for spec in [ZkSpecId::AtlasV4, ZkSpecId::AtlasV5] {
        for probe in [
            BASE_TOKEN_HOLDER_ADDRESS,
            REFUND_RECIPIENT,
            L2_BASE_TOKEN_ADDRESS,
        ] {
            assert_eq!(
                balance_cost(spec, probe),
                WARM_STORAGE_READ_COST,
                "{spec:?}, {probe}"
            );
        }
    }
}

#[test]
fn atlas_v3_reads_the_refund_recipient_only_after_execution() {
    assert_eq!(
        balance_cost(ZkSpecId::AtlasV3, REFUND_RECIPIENT),
        COLD_ACCOUNT_ACCESS_COST
    );
}
