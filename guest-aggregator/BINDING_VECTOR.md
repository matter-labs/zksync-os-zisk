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

## Inputs (real 4-batch aggregation session, ZiSK v0.18.0, 2026-07-15)

```text
innerProgramVK   = 0x481748830df5c3b7aa5522333ace2c4b533352637b92fd3c83ecc506c5104ead
rootCVadcopFinal = 0xcf2a309856f107b143836ada112806da71ae11567fa3f2d2050baba5381c7b7d
```

Batch commitments, in order:

```text
commitment_1 = 0x95693fd871251f2a04f558f94852d31d4f7b0cd38b0ee2c746bd2851dc701dca
commitment_2 = 0x4962160e4e0addc72fe2178dbbf3c5882ca1033790bb968d4fa451485987f99b
commitment_3 = 0xe697864dd72ddded6f1818db6618efff8e695714db8492ac50abc9f5d8b6221e
commitment_4 = 0x3cbda79d374329af945a0b1d2d73c87b2cd2cadb69ab3d6c03166a690dfff898
```

## Chain trace

Per-batch public inputs (`commitment >> 32`):

```text
PI[0] = 0x0000000095693fd871251f2a04f558f94852d31d4f7b0cd38b0ee2c746bd2851
PI[1] = 0x000000004962160e4e0addc72fe2178dbbf3c5882ca1033790bb968d4fa45148
PI[2] = 0x00000000e697864dd72ddded6f1818db6618efff8e695714db8492ac50abc9f5
PI[3] = 0x000000003cbda79d374329af945a0b1d2d73c87b2cd2cadb69ab3d6c03166a69
```

Accumulator after each step:

```text
seed (= PI[0]) = 0x0000000095693fd871251f2a04f558f94852d31d4f7b0cd38b0ee2c746bd2851
after PI[1]    = 0x00000000143345f6cd45d8a2c6c11eb56b78f126e1e70063e1e1960b0b10b160
after PI[2]    = 0x000000005168669ca2b6cfcd32f9570fe3e5210369b3e2ad7e035f86373be216
after PI[3]    = 0x000000004e755bc20431285db82f02b677f0fa43b0b4ae7298e2f489e1a45b78
```

## Pinned outputs

```text
chainedPI = 0x000000004e755bc20431285db82f02b677f0fa43b0b4ae7298e2f489e1a45b78
digest    = 0x5f47db9b336cf84b7b7fc49ca77eadb5160e373dc8f12057d719f45d3b2fbd84
```
