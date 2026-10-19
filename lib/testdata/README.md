# Historical wire fixtures

These fixtures pin inputs emitted under earlier wire versions. They are stored as
hex so schema changes remain ordinary reviewable text diffs; tests remove
whitespace and decode them before execution.

| Fixture | Provenance | Spec | Framed SHA-256 | Historical commitment |
|---|---|---|---|---|
| `wire-v3-session-batch-1.hex` | PR #18 commit `25085ac`, `gen_session_inputs`, batch 1 | AtlasV2 / minor 30 | `cd7213bd6fbc745787212cc09df350da1bfcd30b199121e37899e16400f4d195` | `0x0b34f54c4edd64be7d7b6bcfa09edddc22a7b87e14a253191e8fd521f087914a` |
| `wire-v3-atlas-v3.hex` | The unchanged wire-v3 library at PR #18 commit `25085ac`, existing `coinbase_reward_is_full_effective_gas_price` honest input | AtlasV3 / minor 31 | `3c373b2040f1cf7960c3baeaa741f0a7fbf878c109b70f47e1dc9ddb0e9967e1` | `0x4e101c4291eebeb63b52cd9be88da5a9ab03307500663aab4805aad5da7e4cca` |
| `wire-v5-atlas-v4.hex` | The wire-v5 library at release 0.0.8 commit `d5b1571`, `atlas_v4_transfer_batch(History::Contract)` | AtlasV4 / minor 32 | `5c53823c53cd1659e9617478410b47c9568637077bdd387fa7e37abe40b4c9d1` | `0xbe97814867f143a0cb4610871ee81a14a0ab943f9d7374606e2142aea8c96810` |

All files use the ZiSK stdin frame `[wire length: u64 LE][bincode][zero
padding to 8 bytes]`. The regression tests check exact decode/re-encode under
the frozen schema of their version, normalization, collecting execution,
streaming guest execution, and the pinned commitment.
