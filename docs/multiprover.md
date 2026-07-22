# The ZKsync OS multi-proof lane

One state transition, two independent provers: every batch is proven by
**Airbender** (the primary RV32I prover running the native ZKsync OS binary)
and by **ZiSK** (an RV64IMA zkVM running an independent REVM-based
re-implementation of the state transition), and L1 verification requires
both. A bug in either implementation, compiler, or proof system surfaces as
a proof mismatch instead of a silent state corruption.

The lane rolls out testnet-first on its way to production; every stage is
config-gated and off by default until enabled for a chain.

## Repository map

| Repository | Role |
|---|---|
| `matter-labs/zksync-os-zisk` (this repo) | The ZiSK side end to end: the REVM re-implementation (`lib/`), the zkVM guest (`guest/`), the range aggregator guest (`guest-aggregator/`), the proving daemon (`prover/`), and the EEST conformance lane (`tools/`). |
| `matter-labs/zksync-os-revm` | The REVM extension crate the re-implementation executes on: ZKsync OS system-contract precompiles, L2→L1 log collection, spec gating. |
| `matter-labs/zksync-os-server` | Second-proof-system input generation, the `/prover-jobs/v1/ZiSK/*` API, shadow re-execution equivalence, the multiproof rendezvous and L1 submission, and the range aggregation stage. |
| `matter-labs/era-contracts` | `ZiskVerifier` (Plonk SNARK over the 320-byte public values), `MultiProofVerifier` (combined type-5 proof), aggregated range mode, deployment dispatch. |

## Proof flow

### Per batch

1. **Input generation** (server, `second_proof_system`): at batch seal, the
   server assembles a `BatchInput` — blocks, state reads, preimages and
   batch-boundary tree data — bincode-encoded next to the Airbender witness.
2. **ZiSK job** (server): a job per batch is served over
   `/prover-jobs/v1/ZiSK/*`. Proving starts immediately, in parallel with
   the Airbender FRI/SNARK lane.
3. **Proving** (this repo, `prover/`): the daemon fetches the input and
   runs `cargo-zisk` over the guest ELF (GPU or CPU); the guest re-executes
   the batch on the `lib/` executor and commits the batch commitment in its
   publics. Mirroring Airbender's FRI-per-batch / SNARK-per-range split,
   the per-batch proof is a STARK (`vadcop_final`); the Plonk SNARK is
   produced once per L1 submission. In per-batch mode the submission unit
   is a single batch, so its proof is wrapped directly; the submission
   carries the 768-byte SNARK plus the 320-byte public values
   `programVK (32) ‖ guest publics (256) ‖ rootCVadcopFinal (32)`.
4. **Verification at submission** (server): wire format, batch commitment
   and the configured `zisk_program_vk` tripwire are checked before the
   proof is accepted.
5. **Rendezvous** (server): the SNARK step composes the combined type-5
   payload — Airbender SNARK plus ZiSK proof — from whichever proof
   arrives last.
6. **L1** (era-contracts): `MultiProofVerifier` verifies the Airbender
   proof, binds the ZiSK public values to the same batch public input, and
   verifies the ZiSK Plonk proof through a standalone snarkJS-generated
   verifier referenced by address.

### Aggregated ranges (`zisk_aggregation`)

When one Airbender SNARK covers a range of batches, the ZiSK side matches
it with ONE aggregated (and once, Plonk-wrapped) proof instead of N
per-batch SNARKs — per batch, only the `vadcop_final` STARK is produced:

- Per-batch `vadcop_final` proof streams are buffered as they arrive.
- The Airbender SNARK range assigned at pick time doubles as the
  aggregation range; the pick is all-or-nothing, so a range never leaves
  the server until every FRI in it exists.
- The aggregator guest (`guest-aggregator/`) verifies one inner proof per
  batch inside the zkVM and commits
  `keccak256(innerProgramVK ‖ rootCVadcopFinal ‖ chainedPI)`, where
  `chainedPI` is the self-seeded chain of batch commitments — exactly what
  the L1 range verifier recomputes from its registered per-batch pins
  (`guest-aggregator/BINDING_VECTOR.md` pins a cross-stack test vector).

## Keys and pinning

Four values identify the lane, and each is pinned at least twice so drift
is caught at the layer that notices first:

| Value | What it is | Pinned in |
|---|---|---|
| guest `programVK` | ROM merkle root of `out/zksync-os-zisk-guest` | `guest/GUEST_PROGRAM_VK`, server `zisk_program_vk` tripwire, L1 `ZiskVerifier` |
| aggregator `programVK` | ROM merkle root of the aggregator ELF | `guest-aggregator/GUEST_PROGRAM_VK`, server `zisk_aggregation.program_vk`, L1 range verifier |
| `rootCVadcopFinal` | ZiSK vadcop-final circuit VK | L1 `ZiskVerifier`, binding digest |
| ZiSK VK hash | `keccak256(programVK ‖ rootCVadcopFinal)`, wire byte order | server `ProvingVersion::ZiskV1`, L1 `verificationKeyHash()` |

The programVKs derive from the exact ELF bytes, so guest binaries come from
pinned-container reproducible builds (`build-guest.sh`,
`build-aggregator.sh`; recorded hashes in `*/GUEST_ELF_SHA256`, checked in
CI). **The `lib/`, `guest/` and `guest-aggregator/` sources are byte-frozen
inputs of those builds** — any change there, including formatting, rotates
the programVKs. Rotations are deliberate: rebuild with `--record`, re-derive
the VK with `cargo-zisk program-setup` on a prover box, and update the
server tripwires, the L1 pins and the proof fixtures together.

## Operating modes and failure semantics

Sequencing is never gated by the second proof: block production and batch
sealing run ahead on both lanes, and proofs gate only L1 finality (the
generic sealing-ahead-of-finality backpressure applies unchanged).

Finality behavior is a two-sided choice:

- **Server** — `require_multi_proof = false`: ZiSK runs alongside and the
  L1 submission is Airbender-only immediately (a shadow/observability
  posture; combined payloads are never sent). `require_multi_proof = true`
  with `multi_proof_wait_timeout = Some(..)`: a batch missing its ZiSK
  proof blocks its SNARK submission for the residual proving time, then
  degrades to Airbender-only. With `None`, it blocks until the operator
  flips the config.
- **Contracts** — the strict `MultiProofVerifier` accepts only the combined
  type-5 proof: with it as the chain's verifier, a missing second proof
  halts finality (the load-bearing security property).
  `MultiProofTestnetVerifier` composes the same verification with the
  testnet escape hatches, so testnets keep finalizing while any real
  submission is still held to the full multiproof.

The independent equivalence teeth run before proving ever starts: the
server's shadow re-execution checks every sealed batch's commitment against
the REVM executor in-process (optionally halting on divergence), and the
EEST corpus lane (`tools/CORPUS.md`) compares guest execution against
native zksync-os over the Ethereum execution-spec tests.

## Component documentation

- `guest/` and reproducible builds: repository `README.md`
- Proving daemon and its API contract: `prover/README.md`
- Aggregator binding digest and test vector: `guest-aggregator/BINDING_VECTOR.md`
- Conformance corpus: `tools/CORPUS.md`
- L1 verifier generation and deployment: `era-contracts` →
  `l1-contracts/contracts/state-transition/verifiers/README.md`
