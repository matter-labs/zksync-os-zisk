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
            "zisk_version": "1.2.0-alpha",
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
                    "wire_version": 5,
                    "spec_id": 3,
                    "protocol_version_minor": 32,
                    "framed_input_sha256": f"{index}" * 64,
                    "native_commitment": commitments[index - 1],
                }
                for index in range(1, 5)
            ],
        },
        "proved_commitments": commitments,
        "range_public_input": word(0x21),
        "binding_digest": digest,
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
        vadcop = self.copy("prover/tests/data/real_vadcop_final_zisk_v1.2.0-alpha.bin")
        source_vadcop = self.root / "new-vadcop.bin"
        source_vadcop.write_bytes(b"new validated proof")

        fixture_session.update_repository(self.root, values(), source_vadcop)

        self.assertIn("wire-v5 protocol-v32", doc.read_text())
        self.assertIn("AtlasV4 fixtures", doc.read_text())
        self.assertIn(word(0x31)[2:], guest.read_text())
        self.assertIn(word(0x41)[2:], guest.read_text())
        self.assertIn(word(0x31)[2:], prover.read_text())
        self.assertIn(word(0x11)[2:], prover.read_text())
        self.assertEqual(vadcop.read_bytes(), b"new validated proof")

if __name__ == "__main__":
    unittest.main()
