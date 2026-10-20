# Aggregated-Range Binding Vector

Cross-stack test vector for the aggregator guest's committed output — the
32 bytes at `publics[32..96]` of an aggregated range proof. Three
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

## Inputs (real 4-batch aggregation session, ZiSK v1.3.2-alpha, 2026-10-19)

This vector was produced by [fixture-session run](https://github.com/matter-labs/zksync-os-zisk/actions/runs/39274149227) from
`ci/fixture-session-rtx6000` at `df9a0ddf6d19e317d0f7b111a098afc99636fa5b`. The inputs are
deterministic wire-v6 protocol-v32 AtlasV4 fixtures (wire version 6, spec ID 3,
protocol minor 32), encoded by `tools/test-utils` and executed natively through
the version-dispatching bincode entry point. They carry the four-word public
input shape, including `chainConfigHash`, used by the current settlement
contracts. The proofs use the current guest ELF and current inner programVK.

Native commitments from `input-manifest.json` were automatically compared,
in batch order, with the commitments extracted from all four guest proofs
before PLONK wrapping or recursive proving. All four pairs were equal.

Session data: inner ELF SHA-256
`64a9b91c204fee1d8f8b7a6b258d31977902847a2e66a50c3451026a577a29d4`, aggregator ELF SHA-256
`2c32095410aa67c1bb08119212ab12ef23dece381d576a087e44078795c7b126`.

Framed inputs:

- `batch-1.bin`: framed SHA-256 `ea6d4b2b850978515ce8f211de84d320e7ef11bedc9d8f6f21ca627c2f4c5ff4`
- `batch-2.bin`: framed SHA-256 `d45789841e4aa3ca3b0ff9c5a8115eb8f81381ae9518662139972dd239c0742a`
- `batch-3.bin`: framed SHA-256 `bca6e66286ee742f21e772029034c3b16f3bbe124f5cb6c7a514514b1e583704`
- `batch-4.bin`: framed SHA-256 `7fecab39d8986e976d53ec78333d687546bd0a8485617877bef8caa979d71ea5`

```text
innerProgramVK   = 0x09ebc4f2e17b20d69b6f2850ddfe187ba5b0514abffbcf789823cc6e4e44ef02
rootCVadcopFinal = 0x6b2490fba336fb00f0c8719a961de309a8db6f43a9bfb7575ca5f014d609b265
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
digest           = 0xec1bf9cd08fde7ce771e6ceb96064b0fa73b3a475e7f6da8675989c3c40b13a2
```

The real aggregated proof of this range commits the same digest: the
PLONK-wrapped aggregate has wire public-values bytes `[32..96]` equal to
`digest`, bytes `[0..32]` equal to the aggregator programVK
`0x9e2ea93a5e08c2ddb5b93323a593ada955dc74d00fac433d45c97da5b90e5e08`, and bytes `[544..576]` equal to
`rootCVadcopFinal`.

The fixture publisher automatically updates this document,
`guest-aggregator/src/lib.rs`, `prover/tests/real_aggregation_vector.rs`, and
`prover/tests/data/real_vadcop_final_zisk_v1.3.2-alpha.bin` in a separate PR.
