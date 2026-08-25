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

## Inputs (real 4-batch aggregation session, ZiSK v0.18.0, 2026-08-21)

The inputs below come from a real proving session. Session data: guest ELF
sha256
`80b841c76445dd3c411cc1f11447cc85285521541378821442aef1f7262da932`,
guest repo @ `055e720` (tag 0.0.2), 4 sealed v31 batches of a
`CURRENT_TO_MULTIPROVER_L1` test chain, proved by the server repo's
zisk-fixture-session workflow (run 32503874362) with both programVKs
calibrated against the pins before proving.

Future rotations use this repo's dispatch-only
`.github/workflows/fixture-session.yaml`. Its inputs are deterministic wire-v5
protocol-v32 AtlasV4 fixtures (spec ID 3, protocol minor 32) built by
`tools/test-utils` — no server-sealed batches are involved. They include the
v5 chain configuration, authenticated interop boundary reads, the EIP-2935
history-account proof and a sealed AtlasV4 block header. Their four-word public
input includes `chainConfigHash`, matching the current settlement-contract
shape. The proofs use the current guest ELF and current inner programVK. Before
PLONK wrapping or aggregation, the workflow automatically compares the native
manifest commitment with the commitment extracted from each of the four guest
proofs, in order.

The separate publisher job updates this document,
`guest-aggregator/src/lib.rs`, `prover/tests/real_aggregation_vector.rs`, and
`prover/tests/data/real_vadcop_final_zisk_v0.18.0.bin` through an automation
PR.
Real-batch end-to-end coverage remains in zksync-os-server's prover-tests CI.

```text
innerProgramVK   = 0x44e3d132399c8f3a03ce9672ba0ca00c6503db918731c7ab46d6faea445236ec
rootCVadcopFinal = 0xcf2a309856f107b143836ada112806da71ae11567fa3f2d2050baba5381c7b7d
```

Batch commitments, in order:

```text
commitment_1 = 0x5aa9a30847d37bb20955cfe6a65c916d4d0c504c8e5bb0965db8a90aba1e9938
commitment_2 = 0x167bf6f9edbe48835b6b60e98af53552b0126765a804b86a3d7749daf05a5f4e
commitment_3 = 0x8f03a8b3b8b78ef7ab5004817c9ebf211b09533b9a0ad86440396f4605ab794b
commitment_4 = 0x3db0606d441cb57e9c621be9052e759db43e7c5c608c6e810ce673d9a4503c45
```

## Fold trace

The four per-batch public inputs enter the keccak untruncated, in batch
order, as one 128-byte preimage:

```text
preimage = commitment_1 ‖ commitment_2 ‖ commitment_3 ‖ commitment_4
keccak256(preimage) = 0xa71a9887b866c0837965ac66c2710d8232871ba878798109a919ea017b3d10b5
rangePublicInput    = 0x00000000a71a9887b866c0837965ac66c2710d8232871ba878798109a919ea01
```

This vector holds one range size. `range_sizes_match_the_settlement_formula`
in `src/lib.rs` pins N = 1, N = 2 and N = 4 over a commitment set of its
own, which no session rotation moves, and so covers both branches of the
formula.

## Pinned outputs

```text
rangePublicInput = 0x00000000a71a9887b866c0837965ac66c2710d8232871ba878798109a919ea01
digest           = 0x15fd80a250aa290d7bbf88b214a78cfed6f9fc1c8a094dae82762739f1e7fbf5
```

## Provenance of each number

Computed from the formula above, over the recorded session commitments,
and reproducible with any keccak tool:

- `keccak256(preimage)`, `rangePublicInput` and `digest`.

Recorded from the real proving session:

- `innerProgramVK`, `rootCVadcopFinal`, `commitment_1` … `commitment_4`,
  and the inner guest ELF sha256. These come from the state-transition
  guest and the ZiSK v0.18.0 setup, both outside the aggregator fold, so
  the per-batch proofs and the committed batch-1 fixture hold.

Pending a prover box:

- the aggregator programVK, which rotates with the aggregator ELF (sha256
  `d886c4cdfa10e8c106592f8698504b6fd4df619e0889974a792bf7e6762a2bb8`;
  `GUEST_PROGRAM_VK` carries the pending marker and the derivation
  command),
- an aggregated range proof that commits `digest` at wire public-values
  bytes `[32..64]`. Run `.github/workflows/fixture-session.yaml` to
  produce one, and record the aggregator programVK it reports at wire
  public-values bytes `[0..32]`.
