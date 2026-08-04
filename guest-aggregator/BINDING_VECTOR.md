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

## Inputs (real 4-batch aggregation session, ZiSK v0.18.0, 2026-08-04)

Session data: guest ELF sha256
`32911f12d4ed76827d29bd04884972e865f188a5d2d03bcbf776f5dc0351f079`,
aggregator ELF sha256
`f96f9285ca87083f322569d72fd379b67b1ee2ea3286c078c26e313acd27e7ae`,
server `multiprover-upstream` @ `44dd3113`, guest repo @ `f6065882`,
4 sealed v31 batches of a `NEXT_TO_L1` test chain.

```text
innerProgramVK   = 0x1d16f620e2bc7e58044df7ee8d4284422a0dd37cf151cf79ecf324c131e50468
rootCVadcopFinal = 0xcf2a309856f107b143836ada112806da71ae11567fa3f2d2050baba5381c7b7d
```

Batch commitments, in order:

```text
commitment_1 = 0x6c41981c6fd0bd9a9262fe3dcc9fe4f0d8e142651f80316a8846d6922b5214ea
commitment_2 = 0x1f56fcbd24636dc0a635bc51808d7db9eabf3914f66611c93cf37ea440a5fe27
commitment_3 = 0x9d909d7416f29633c361bfc00073a9004423f0e1cc46105cdd24550543c0e41c
commitment_4 = 0x6ca5ada4916397cfb1b07a2f115f21fedf7e4a14a827995b3c5b392966532ad6
```

## Chain trace

Per-batch public inputs (`commitment >> 32`):

```text
PI[0] = 0x000000006c41981c6fd0bd9a9262fe3dcc9fe4f0d8e142651f80316a8846d692
PI[1] = 0x000000001f56fcbd24636dc0a635bc51808d7db9eabf3914f66611c93cf37ea4
PI[2] = 0x000000009d909d7416f29633c361bfc00073a9004423f0e1cc46105cdd245505
PI[3] = 0x000000006ca5ada4916397cfb1b07a2f115f21fedf7e4a14a827995b3c5b3929
```

Accumulator after each step:

```text
seed (= PI[0]) = 0x000000006c41981c6fd0bd9a9262fe3dcc9fe4f0d8e142651f80316a8846d692
after PI[1]    = 0x00000000e5c55d4eb838c2759f4e4ca50ae9329ac3c72252168f069bd795a276
after PI[2]    = 0x00000000276b0aa43c96c688be7b817c0e94ef3a91e8141eca61bed9209b2de0
after PI[3]    = 0x00000000aef7dc22681088617d4cefece2e7afcc23e776dd7694c967ad5e5603
```

## Pinned outputs

```text
chainedPI = 0x00000000aef7dc22681088617d4cefece2e7afcc23e776dd7694c967ad5e5603
digest    = 0x7eabba6c7a68150706e10101195be54eaf3b39f699bc8da5f34c8033eedec13e
```

The real aggregated proof of this range commits the same digest: the
PLONK-wrapped aggregate has wire public-values bytes `[32..64]` equal to
`digest`, bytes `[0..32]` equal to the aggregator programVK
`0x4c3d7317a62f651d813ba6afbbce59e45eaa7c009ab2a9b51d2f0fb3e7987254`, and
bytes `[288..320]` equal to `rootCVadcopFinal`.
