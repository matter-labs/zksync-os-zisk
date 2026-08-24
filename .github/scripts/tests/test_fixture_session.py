from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / ".github/scripts/apply-fixture-session.py"


def load_script():
    spec = importlib.util.spec_from_file_location("apply_fixture_session", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture_session = load_script()


def word(byte: int) -> str:
    return "0x" + f"{byte:02x}" * 32


def values() -> dict:
    commitments = [word(value) for value in range(0x11, 0x15)]
    trace = [word(value) for value in range(0x21, 0x25)]
    inner = word(0x31)
    aggregator = word(0x32)
    root = word(0x33)
    digest = word(0x41)
    return {
        "schema_version": 1,
        "metadata": {
            "selected_ref": "ci/fixture-session",
            "selected_sha": "a" * 40,
            "run_url": "https://github.com/matter-labs/zksync-os-zisk/actions/runs/1",
            "session_date": "2026-08-24",
            "zisk_version": "0.18.0",
            "inner_elf_sha256": "b" * 64,
            "aggregator_elf_sha256": "c" * 64,
            "inner_program_vk": inner,
            "aggregator_program_vk": aggregator,
            "root_c_vadcop_final": root,
        },
        "input_manifest": {
            "schema_version": 1,
            "batches": [
                {
                    "input_filename": f"batch-{index}.bin",
                    "wire_version": 3,
                    "spec_id": 1,
                    "protocol_version_minor": 30,
                    "framed_input_sha256": f"{index}" * 64,
                    "native_commitment": commitments[index - 1],
                }
                for index in range(1, 5)
            ],
        },
        "proved_commitments": commitments,
        "chained_trace": trace,
        "chained_pi": trace[-1],
        "binding_digest": digest,
        "batch_proof": "aa" * 768,
        "batch_public_values": inner[2:] + commitments[0][2:] + "00" * 224 + root[2:],
        "aggregated_proof": "cc" * 768,
        "aggregated_public_values": aggregator[2:] + digest[2:] + "00" * 224 + root[2:],
    }


class FixturePublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def copy(self, relative: str) -> Path:
        destination = self.root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
        return destination

    def test_updates_exact_repository_fixture_sites(self) -> None:
        doc = self.copy("guest-aggregator/BINDING_VECTOR.md")
        guest = self.copy("guest-aggregator/src/lib.rs")
        prover = self.copy("prover/tests/real_aggregation_vector.rs")
        vadcop = self.copy("prover/tests/data/real_vadcop_final_zisk_v0.18.0.bin")
        source_vadcop = self.root / "new-vadcop.bin"
        source_vadcop.write_bytes(b"new validated proof")

        fixture_session.update_repository(self.root, values(), source_vadcop)

        self.assertIn("intentionally frozen wire-v3", doc.read_text())
        self.assertIn("AtlasV2 fixtures", doc.read_text())
        self.assertIn(word(0x31)[2:], guest.read_text())
        self.assertIn(word(0x41)[2:], guest.read_text())
        self.assertIn(word(0x31)[2:], prover.read_text())
        self.assertIn(word(0x11)[2:], prover.read_text())
        self.assertEqual(vadcop.read_bytes(), b"new validated proof")

    def test_updates_both_external_era_contracts_tests(self) -> None:
        relative = Path("l1-contracts/test/foundry/l1/unit/concrete/Verifier")
        directory = self.root / relative
        directory.mkdir(parents=True)
        range_words = [
            "INNER_PROGRAM_VK",
            "AGGREGATOR_PROGRAM_VK",
            "ROOT_C_VADCOP_FINAL",
            "COMMITMENT_1",
            "COMMITMENT_2",
            "COMMITMENT_3",
            "COMMITMENT_4",
            "CHAINED_PI",
            "DIGEST",
        ]
        (directory / "MultiProofRangeVectorTest.t.sol").write_text(
            "\n".join(
                f"bytes32 internal constant {name} = {word(0)};" for name in range_words
            )
            + "\n"
        )
        proof_source = "\n".join(
            [
                'bytes internal constant BATCH_PROOF = hex"00";',
                'bytes internal constant BATCH_PUBLIC_VALUES = hex"00";',
                'bytes internal constant AGGREGATED_PROOF = hex"00";',
                'bytes internal constant AGGREGATED_PUBLIC_VALUES = hex"00";',
            ]
            + [
                f"bytes32 internal constant COMMITMENT_{index} = {word(0)};"
                for index in range(1, 5)
            ]
        )
        proof_path = directory / "ZiskVerifierRealProofTest.t.sol"
        proof_path.write_text(proof_source + "\n")

        fixture_session.update_era_contracts(self.root, values())

        range_result = (directory / "MultiProofRangeVectorTest.t.sol").read_text()
        proof_result = proof_path.read_text()
        self.assertIn(word(0x31), range_result)
        self.assertIn(word(0x41), range_result)
        self.assertIn('hex"' + "aa" * 768 + '"', proof_result)
        expected_publics = word(0x32)[2:] + word(0x41)[2:] + "00" * 224 + word(0x33)[2:]
        self.assertIn('hex"' + expected_publics + '"', proof_result)
        self.assertIn(word(0x14), proof_result)


if __name__ == "__main__":
    unittest.main()
