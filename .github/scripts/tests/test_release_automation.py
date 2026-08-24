from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1]
ROTATE_SCRIPT = SCRIPTS / "rotate-program-vk.py"


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release_assets = load_script("build_release_assets", SCRIPTS / "build-release-assets.py")


def canonical(limbs: list[int]) -> str:
    return "0x" + b"".join(limb.to_bytes(8, "big") for limb in limbs).hex()


def verkey(limbs: list[int]) -> bytes:
    return b"".join(limb.to_bytes(8, "little") for limb in limbs)


class RotateProgramVkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.elf = self.root / "guest"
        self.elf.write_bytes(b"reviewed guest ELF")
        self.elf_sha_record = self.root / "GUEST_ELF_SHA256"
        elf_digest = hashlib.sha256(self.elf.read_bytes()).hexdigest()
        self.elf_sha_record.write_text(f"{elf_digest}  guest\n")
        self.record = self.root / "GUEST_PROGRAM_VK"
        self.recorded_limbs = [1, 2, 3, 4]
        self.recorded = canonical(self.recorded_limbs)
        self.record.write_text(
            f"# reviewed pin\n{self.recorded}\n\n"
            "# History: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_rotation(self, limbs: list[int], update: bool = False) -> dict[str, object]:
        verkey_path = self.root / "program.verkey.bin"
        verkey_path.write_bytes(verkey(limbs))
        metadata = self.root / "metadata.json"
        command = [
            sys.executable,
            str(ROTATE_SCRIPT),
            "--kind",
            "inner",
            "--elf",
            str(self.elf),
            "--elf-sha-record",
            str(self.elf_sha_record),
            "--verkey",
            str(verkey_path),
            "--record",
            str(self.record),
            "--zisk-version",
            "0.18.0",
            "--date",
            "2026-08-24",
            "--run-url",
            "https://github.com/matter-labs/zksync-os-zisk/actions/runs/123",
            "--metadata",
            str(metadata),
        ]
        if update:
            command.append("--update")
        subprocess.run(
            command,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return json.loads(metadata.read_text())

    def test_current_pin_does_not_rewrite_record(self) -> None:
        before = self.record.read_bytes()
        metadata = self.run_rotation(self.recorded_limbs, update=True)
        self.assertEqual(self.record.read_bytes(), before)
        self.assertFalse(metadata["changed"])
        self.assertFalse(metadata["updated"])

    def test_unapproved_change_is_reported_without_rewrite(self) -> None:
        before = self.record.read_bytes()
        metadata = self.run_rotation([5, 6, 7, 8])
        self.assertEqual(self.record.read_bytes(), before)
        self.assertTrue(metadata["changed"])
        self.assertFalse(metadata["updated"])

    def test_elf_digest_must_match_reviewed_pin(self) -> None:
        before = self.record.read_bytes()
        self.elf_sha_record.write_text(f"{'0' * 64}  guest\n")
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_rotation([5, 6, 7, 8], update=True)
        self.assertEqual(self.record.read_bytes(), before)

    def test_approved_change_updates_pin_and_preserves_history(self) -> None:
        derived_limbs = [5, 6, 7, 8]
        derived = canonical(derived_limbs)
        metadata = self.run_rotation(derived_limbs, update=True)
        result = self.record.read_text()
        self.assertIn(f"\n{derived}\n", result)
        self.assertIn(f"# History: {self.recorded}", result)
        self.assertIn("# History: 0xffffffffffff", result)
        self.assertTrue(metadata["changed"])
        self.assertTrue(metadata["updated"])
        self.assertEqual(metadata["program_vk_limbs"], derived_limbs)

    def test_pending_record_can_be_filled_by_authorized_rotation(self) -> None:
        self.record.write_text(
            "# programVK awaits the official proving-key derivation\nPENDING\n"
        )
        derived_limbs = [9, 10, 11, 12]
        derived = canonical(derived_limbs)
        metadata = self.run_rotation(derived_limbs, update=True)
        result = self.record.read_text()
        self.assertIn(f"\n{derived}\n", result)
        self.assertNotIn("PENDING", result)
        self.assertNotIn("# History: PENDING", result)
        self.assertIsNone(metadata["recorded_program_vk"])
        self.assertTrue(metadata["changed"])
        self.assertTrue(metadata["updated"])


class ReleaseSummaryTests(unittest.TestCase):
    def test_summary_contains_operator_identities(self) -> None:
        manifest = {
            "release": {"tag": "1.2.3", "commit": "a" * 40},
            "toolchain": {"zisk_version": "0.18.0"},
            "programs": {
                "inner": {
                    "elf": {"sha256": "b" * 64},
                    "program_vk": canonical([1, 2, 3, 4]),
                    "program_vk_limbs": [1, 2, 3, 4],
                },
                "aggregator": {
                    "elf": {"sha256": "c" * 64},
                    "program_vk": canonical([5, 6, 7, 8]),
                    "program_vk_limbs": [5, 6, 7, 8],
                },
            },
            "vadcop_final": {
                "root_c": canonical([9, 10, 11, 12]),
                "root_c_limbs": [9, 10, 11, 12],
            },
            "zisk_verification_key_hash": "0x" + "d" * 64,
        }
        with tempfile.TemporaryDirectory() as temporary:
            summary = Path(temporary) / "summary.md"
            release_assets.append_summary(summary, manifest)
            result = summary.read_text()
        self.assertIn("## ZiSK release identities", result)
        self.assertIn("ZiSK `0.18.0`", result)
        self.assertIn("`[1, 2, 3, 4]`", result)
        self.assertIn("`[9, 10, 11, 12]`", result)
        self.assertIn("0x" + "d" * 64, result)


class ReleaseAssetsTests(unittest.TestCase):
    def test_builds_four_file_vk_bundle_with_elf_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inner_elf = root / "inner-elf"
            aggregator_elf = root / "aggregator-elf"
            inner_elf.write_bytes(b"inner ELF")
            aggregator_elf.write_bytes(b"aggregator ELF")
            guest_archive = root / "zksync-os-zisk-guest-elfs-1.2.3.tar.gz"
            prover_archive = (
                root / "zksync-os-zisk-prover-1.2.3-x86_64-unknown-linux-gnu.tar.gz"
            )
            prover_service = root / "zksync-os-zisk-prover-service"
            guest_archive.write_bytes(b"guest archive")
            prover_archive.write_bytes(b"prover archive")
            prover_service.write_bytes(b"prover service")

            inner_limbs = [1, 2, 3, 4]
            aggregator_limbs = [5, 6, 7, 8]
            vadcop_limbs = [9, 10, 11, 12]
            inner_verkey = root / "inner.verkey.bin"
            aggregator_verkey = root / "aggregator.verkey.bin"
            vadcop_verkey = root / "vadcop.verkey.bin"
            inner_verkey.write_bytes(verkey(inner_limbs))
            aggregator_verkey.write_bytes(verkey(aggregator_limbs))
            vadcop_verkey.write_bytes(verkey(vadcop_limbs))

            inner_record = root / "inner-record"
            aggregator_record = root / "aggregator-record"
            inner_record.write_text(canonical(inner_limbs) + "\n")
            aggregator_record.write_text(canonical(aggregator_limbs) + "\n")
            output = root / "output"
            summary = root / "summary.md"

            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "build-release-assets.py"),
                    "--tag",
                    "1.2.3",
                    "--commit",
                    "a" * 40,
                    "--zisk-version",
                    "0.18.0",
                    "--inner-elf",
                    str(inner_elf),
                    "--inner-verkey",
                    str(inner_verkey),
                    "--inner-record",
                    str(inner_record),
                    "--aggregator-elf",
                    str(aggregator_elf),
                    "--aggregator-verkey",
                    str(aggregator_verkey),
                    "--aggregator-record",
                    str(aggregator_record),
                    "--vadcop-verkey",
                    str(vadcop_verkey),
                    "--guest-archive",
                    str(guest_archive),
                    "--prover-archive",
                    str(prover_archive),
                    "--prover-service",
                    str(prover_service),
                    "--output",
                    str(output),
                    "--summary",
                    str(summary),
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    "zksync-os-zisk-guest.verkey.bin",
                    "zksync-os-zisk-guest-aggregator.verkey.bin",
                    "zisk-vadcop-final.verkey.bin",
                    "zisk-release.json",
                },
            )
            manifest = json.loads((output / "zisk-release.json").read_text())
            self.assertEqual(manifest["schema_version"], 1)
            self.assertEqual(
                manifest["programs"]["inner"]["elf"],
                {
                    "asset": "zksync-os-zisk-guest",
                    "sha256": hashlib.sha256(inner_elf.read_bytes()).hexdigest(),
                    "size": len(inner_elf.read_bytes()),
                },
            )
            self.assertEqual(
                manifest["programs"]["aggregator"]["program_vk"],
                canonical(aggregator_limbs),
            )
            self.assertEqual(
                manifest["artifacts"]["prover_service"],
                {
                    "asset": "zksync-os-zisk-prover-service",
                    "sha256": hashlib.sha256(prover_service.read_bytes()).hexdigest(),
                    "size": len(prover_service.read_bytes()),
                },
            )
            self.assertEqual(
                manifest["artifacts"]["guest_archive"]["asset"],
                guest_archive.name,
            )
            self.assertEqual(
                manifest["artifacts"]["prover_archive"]["asset"],
                prover_archive.name,
            )
            self.assertTrue(summary.read_text().startswith("## ZiSK release identities"))


if __name__ == "__main__":
    unittest.main()
