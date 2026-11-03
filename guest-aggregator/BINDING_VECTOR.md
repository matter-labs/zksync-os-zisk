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
  big-endian each, in order (wire public-values bytes `[544..576]`).
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
  batch i's full 32-byte commitment (the guest publics of its ZiSK proof,
  wire public-values bytes `[32..96]` at one u32 per eight-byte slot) read
  as a big-endian uint256. The fold consumes it
  untruncated. `PUBLIC_INPUT_SHIFT` applies once, to the folded result,
  so `rangePublicInput` is 224-bit and its top 4 bytes are zero.

The settlement layer rejects a non-zero carried hash, so a range carries
no continuation input.

## Inputs (real 4-batch aggregation session, ZiSK v1.4.0-alpha, 2026-11-03)

This vector was produced by [fixture-session run](https://github.com/matter-labs/zksync-os-zisk/actions/runs/41671348755) from
`alo/zisk-1.4.0-alpha` at `ade1ce58ab3164821267bc7e2bf15cc382b83d04`. The inputs are
deterministic wire-v6 protocol-v32 AtlasV4 fixtures (wire version 6, spec ID 3,
protocol minor 32), encoded by `tools/test-utils` and executed natively through
the version-dispatching bincode entry point. They carry the four-word public
input shape, including `chainConfigHash`, used by the current settlement
contracts. The proofs use the current guest ELF and current inner programVK.

Native commitments from `input-manifest.json` were automatically compared,
in batch order, with the commitments extracted from all four guest proofs
before the SNARK wrap or recursive proving. All four pairs were equal.

Session data: inner ELF SHA-256
`ed7a53e344a183f9b6660896a477eede76c907c3bd62fe9a466521b538372c59`, aggregator ELF SHA-256
`a438ea097e2ef18f9328a7d7e087c261cf6261813ae8f71cb0e586420c4f4065`.

Framed inputs:

- `batch-1.bin`: framed SHA-256 `ea6d4b2b850978515ce8f211de84d320e7ef11bedc9d8f6f21ca627c2f4c5ff4`
- `batch-2.bin`: framed SHA-256 `d45789841e4aa3ca3b0ff9c5a8115eb8f81381ae9518662139972dd239c0742a`
- `batch-3.bin`: framed SHA-256 `bca6e66286ee742f21e772029034c3b16f3bbe124f5cb6c7a514514b1e583704`
- `batch-4.bin`: framed SHA-256 `7fecab39d8986e976d53ec78333d687546bd0a8485617877bef8caa979d71ea5`

```text
innerProgramVK   = 0x747be84de38d60d9b5816ddad433d41c9771825b630bddbc90cb1585dda69a6c
rootCVadcopFinal = 0xe9414e134bb6945a148a79d44c8e850e5ef582a2b0e8dbfb2428ff0a515a6e66
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
digest           = 0x5afe2e89a27ddd841b343cff7fb3a9f3c0dc18b0d6bc7d685fbfa55af59c9bd0
```

The real aggregated proof of this range commits the same digest: the
pilfflonk-wrapped aggregate carries `digest` in its guest publics (wire
public-values bytes `[32..96]`, one u32 per eight-byte slot), the aggregator
programVK `0xe7f72bf4c1825a6f852e65fc872c810320218c63ed41cf9bb4345737a4ac31ec` in bytes `[0..32]`, and
`rootCVadcopFinal` in bytes `[544..576]`.

The fixture publisher automatically updates this document,
`guest-aggregator/src/lib.rs`, `prover/tests/real_aggregation_vector.rs`,
`prover/tests/real_proof_parse.rs`, `prover/tests/data/real_vadcop_final_zisk_v1.4.0-alpha.bin`, and
`prover/tests/data/real_pilfflonk_aggregate_zisk_v1.4.0-alpha.bin` in a separate PR.
