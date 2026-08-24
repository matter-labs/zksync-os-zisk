# Aggregated-Range Binding Vector

Cross-stack test vector for the aggregator guest's committed output — the
32 bytes at `publics[32..64]` of an aggregated range proof. Three
codebases pin these exact values and must stay in lockstep:

- this guest (`cross_stack_binding_vector` in `src/lib.rs` and the
  real-proof test in `prover/tests/real_aggregation_vector.rs`),
- the server's aggregation job validation,
- the L1 `MultiProofVerifier` integration tests.

Update all pins together whenever any input rotates.

## Formula

```text
digest = keccak256(innerProgramVK ‖ rootCVadcopFinal ‖ chainedPI)
```

- `innerProgramVK` — 32 bytes: the STF guest's 4 ROM-root u64 limbs,
  big-endian each, in order (wire public-values bytes `[0..32]`).
- `rootCVadcopFinal` — 32 bytes: the 4 vadcop-final VK u64 limbs,
  big-endian each, in order (wire public-values bytes `[288..320]`).
- `chainedPI` — 32-byte big-endian uint256:
  `MultiProofVerifier._computeZKsyncOSHash(0, PI)` over the per-batch
  public inputs in batch order:

  ```text
  result = PI[0]                                      // initialHash == 0
  for i in 1..N:
      result = uint256(keccak256(abi.encodePacked(result, PI[i]))) >> 32
  chainedPI = result
  ```

- `PI[i]` — the per-batch public input as L1 consumes it:
  `uint256(commitment_i) >> 32`, where `commitment_i` is batch i's full
  32-byte commitment (wire public-values bytes `[32..64]` of its ZiSK
  proof) read as a big-endian uint256. Every chain value is 224-bit
  (`PUBLIC_INPUT_SHIFT = 32`), carried as a 32-byte big-endian word with
  the top 4 bytes zero.

## Inputs (real 4-batch aggregation session, ZiSK v0.18.0, 2026-08-21)

Session data: guest ELF sha256
`80b841c76445dd3c411cc1f11447cc85285521541378821442aef1f7262da932`,
aggregator ELF sha256
`f96f9285ca87083f322569d72fd379b67b1ee2ea3286c078c26e313acd27e7ae`,
guest repo @ `055e720` (tag 0.0.2), 4 sealed v31 batches of a
`CURRENT_TO_MULTIPROVER_L1` test chain, proved by the server repo's
zisk-fixture-session workflow (run 32503874362) with both programVKs
calibrated against the pins before proving.

Future rotations use this repo's dispatch-only
`.github/workflows/fixture-session.yaml`. Its inputs are intentionally frozen
wire-v3 AtlasV2 fixtures (spec ID 1, protocol minor 30) built by
`tools/test-utils` — no server-sealed batches are involved. The inputs retain
their historical bytes and execution commitments, but their proofs use the
current guest ELF and current inner programVK; wire compatibility does not
preserve the old programVK. Before PLONK wrapping or aggregation, the workflow
automatically compares the native manifest commitment with the commitment
extracted from each of the four guest proofs, in order.

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

## Chain trace

Per-batch public inputs (`commitment >> 32`):

```text
PI[0] = 0x000000005aa9a30847d37bb20955cfe6a65c916d4d0c504c8e5bb0965db8a90a
PI[1] = 0x00000000167bf6f9edbe48835b6b60e98af53552b0126765a804b86a3d7749da
PI[2] = 0x000000008f03a8b3b8b78ef7ab5004817c9ebf211b09533b9a0ad86440396f46
PI[3] = 0x000000003db0606d441cb57e9c621be9052e759db43e7c5c608c6e810ce673d9
```

Accumulator after each step:

```text
seed (= PI[0]) = 0x000000005aa9a30847d37bb20955cfe6a65c916d4d0c504c8e5bb0965db8a90a
after PI[1]    = 0x000000005a28fede239385266dd011a1e789117fb08b78253d2dd4fb3e3e610a
after PI[2]    = 0x000000000fdf9d9edb975a6b6e0bb5a5c771f0ad8d29094bc536542deb275c64
after PI[3]    = 0x0000000076b405f665d8b8b9c069b298656c9ef179632673523db317aeaa88b6
```

## Pinned outputs

```text
chainedPI = 0x0000000076b405f665d8b8b9c069b298656c9ef179632673523db317aeaa88b6
digest    = 0x8d3dc379548b65d0ed7df762dc646bf46fdbdf628cfe483479392ea8159e405b
```

The real aggregated proof of this range commits the same digest: the
PLONK-wrapped aggregate has wire public-values bytes `[32..64]` equal to
`digest`, bytes `[0..32]` equal to the aggregator programVK
`0x4c3d7317a62f651d813ba6afbbce59e45eaa7c009ab2a9b51d2f0fb3e7987254`, and
bytes `[288..320]` equal to `rootCVadcopFinal`.
