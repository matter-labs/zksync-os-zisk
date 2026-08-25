# Aggregated-Range Binding Vector

Cross-stack test vector for the aggregator guest's committed output — the
32 bytes at `publics[32..64]` of an aggregated range proof. Three
codebases pin these exact values and must stay in lockstep:

- this guest (`cross_stack_binding_vector` in `src/lib.rs` and the
  real-proof test in `prover/tests/real_aggregation_vector.rs`),
- the server's aggregation job validation,
- the L1 range-verifier integration tests.

Update all pins together whenever any input rotates.

## Formula

```text
digest = keccak256(innerProgramVK ‖ rootCVadcopFinal ‖ rangePublicInput)
```

- `innerProgramVK` — 32 bytes: the STF guest's 4 ROM-root u64 limbs,
  big-endian each, in order (wire public-values bytes `[0..32]`).
- `rootCVadcopFinal` — 32 bytes: the 4 vadcop-final VK u64 limbs,
  big-endian each, in order (wire public-values bytes `[288..320]`).
- `rangePublicInput` — 32-byte big-endian uint256: the settlement layer's
  `ZKsyncOSVerifier.computeZKsyncOSHash(0, publicInputs)` over the
  per-batch public inputs in batch order:

  ```text
  folded = N == 1 ? PI[0] : uint256(keccak256(abi.encodePacked(PI)))
  rangePublicInput = folded >> PUBLIC_INPUT_SHIFT      // PUBLIC_INPUT_SHIFT = 32
  ```

  A one-batch range performs no keccak. This is an invariant of the
  settlement layer, and single-batch ranges are the common case.

- `PI[i]` — the per-batch public input the settlement layer supplies:
  batch i's full 32-byte commitment (wire public-values bytes `[32..64]`
  of its ZiSK proof) read as a big-endian uint256. The fold consumes it
  untruncated. `PUBLIC_INPUT_SHIFT` applies once, to the folded result,
  so `rangePublicInput` is 224-bit and its top 4 bytes are zero.

The settlement layer rejects a non-zero carried hash, so a range carries
no continuation input.

## Inputs (real 4-batch aggregation session, ZiSK v0.18.0, 2026-08-25)

This vector was produced by [fixture-session run](https://github.com/matter-labs/zksync-os-zisk/actions/runs/32865370312) from
`main` at `0c04ce499f8dc19037fa1b224ba6a17860fc2313`. The inputs are
deterministic wire-v5 protocol-v32 AtlasV4 fixtures (wire version 5, spec ID 3,
protocol minor 32), encoded by `tools/test-utils` and executed natively through
the version-dispatching bincode entry point. They carry the four-word public
input shape, including `chainConfigHash`, used by the current settlement
contracts. The proofs use the current guest ELF and current inner programVK.

Native commitments from `input-manifest.json` were automatically compared,
in batch order, with the commitments extracted from all four guest proofs
before PLONK wrapping or recursive proving. All four pairs were equal.

Session data: inner ELF SHA-256
`ac5b351ee31b3929fb9cb5a63ed3dfbff6609b3af04f1f3d0febfacc12d1c1f3`, aggregator ELF SHA-256
`d886c4cdfa10e8c106592f8698504b6fd4df619e0889974a792bf7e6762a2bb8`.

Framed inputs:

- `batch-1.bin`: framed SHA-256 `35a0a72bd13155c8fcdd397d3c16f0bd43ae9141fed3be0187dd9ad653f4a97e`
- `batch-2.bin`: framed SHA-256 `b3f3492e4a4f890699221dc2518ff30ebafea8b7b7a7e56bd782e91d1e5194c6`
- `batch-3.bin`: framed SHA-256 `449aa9085987334f0f43228a3b9c51b17287284b01962fa0958745cb1780d7b8`
- `batch-4.bin`: framed SHA-256 `72b7f175f112ea7f3f3645cafbc4614f82d4378efd1b35b8523a7c77e2839781`

```text
innerProgramVK   = 0x8168c5d383a50a9c7a40561b82bf679cc6dfdab0308417b4fea653362d78d080
rootCVadcopFinal = 0xcf2a309856f107b143836ada112806da71ae11567fa3f2d2050baba5381c7b7d
```

Batch commitments, in order:

```text
commitment_1 = 0x63c7606faee0ee9eff230fec391e64c0c82a0277947973ce7f6f1c9088c821dd
commitment_2 = 0x7d6a5ed6ffda210164c11dd6f6fccbd35c4ff70632e845a5bf256e3ec48940b9
commitment_3 = 0xd5a7b4485d1aece18348655132e73c86b23fa0f251adb173f80123d05a914f15
commitment_4 = 0xc5ed165443011bac65df4d0f4240de3429c033996e9fce630a631e117537cd61
```

## Fold trace

The per-batch public inputs enter the keccak untruncated, in batch order,
as one 128-byte preimage:

```text
preimage         = commitment_1 ‖ commitment_2 ‖ commitment_3 ‖ commitment_4
rangePublicInput = uint256(keccak256(preimage)) >> 32
```

This vector holds one range size. `range_sizes_match_the_settlement_formula`
in `src/lib.rs` pins N = 1, N = 2 and N = 4 over a commitment set of its
own, which no session rotation moves, and so covers both branches of the
formula.

## Pinned outputs

```text
rangePublicInput = 0x00000000108311cf154dafcd8fbeb3d29ff924941d60db59f523d33baa5d2ca5
digest           = 0xf29341c341f2622ba86a21bbb36dde9742e1983e531c278fd1cee04c6f823e2c
```

The real aggregated proof of this range commits the same digest: the
PLONK-wrapped aggregate has wire public-values bytes `[32..64]` equal to
`digest`, bytes `[0..32]` equal to the aggregator programVK
`0xf68b9862e424e377af7b4220a419ce45bc52ce70b0a37aea486a15a5ca38b738`, and bytes `[288..320]` equal to
`rootCVadcopFinal`.

The fixture publisher automatically updates this document,
`guest-aggregator/src/lib.rs`, `prover/tests/real_aggregation_vector.rs`, and
`prover/tests/data/real_vadcop_final_zisk_v0.18.0.bin` in a separate PR.
