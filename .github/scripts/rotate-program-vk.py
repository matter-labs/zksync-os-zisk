#!/usr/bin/env python3
"""Update one reviewed program-VK pin from a derived ZiSK verkey."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


VK_PATTERN = re.compile(r"^0x[0-9a-f]{64}$", re.MULTILINE)
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
DATE_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?")
RUN_URL_PATTERN = re.compile(r"https://[^\s]+/actions/runs/[0-9]+")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_verkey(path: Path) -> tuple[list[int], str]:
    raw = path.read_bytes()
    if len(raw) != 32:
        raise ValueError(f"{path} has {len(raw)} bytes; expected 32")
    limbs = [
        int.from_bytes(raw[offset : offset + 8], "little")
        for offset in range(0, 32, 8)
    ]
    canonical = "0x" + b"".join(limb.to_bytes(8, "big") for limb in limbs).hex()
    return limbs, canonical


def read_active_vk(path: Path) -> str | None:
    active = [
        line.split("#", 1)[0].strip()
        for line in path.read_text().splitlines()
        if line.split("#", 1)[0].strip()
    ]
    if len(active) != 1:
        raise ValueError(f"{path} must contain exactly one active VK record")
    if active[0] == "PENDING":
        return None
    if VK_PATTERN.fullmatch(active[0]) is None:
        raise ValueError(f"{path} must contain PENDING or one canonical VK")
    return active[0]


def read_recorded_sha256(path: Path) -> str:
    fields = path.read_text().split()
    if not fields or SHA256_PATTERN.fullmatch(fields[0]) is None:
        raise ValueError(f"{path} does not start with a SHA-256 value")
    return fields[0]


def history_tail(source: str) -> str:
    lines = source.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("# History:"):
            return "\n".join(lines[index:]).rstrip()
    return ""


def record_header(kind: str) -> list[str]:
    if kind == "inner":
        return [
            "# programVK (ZiSK ROM merkle root) of the reproducible guest ELF.",
            "# The value covers the ROM image only, so two ELFs that differ outside the",
            "# ROM image share it.",
            "# Serialization: the four ROM root-hash u64 limbs, big-endian, in order —",
            "# identical to the prover daemon's public-values prefix and the server's",
            "# `prover_api.zisk_vks[].program_vk` expectation.",
        ]
    return [
        "# programVK (ZiSK ROM merkle root) of the aggregator guest ELF with the",
        "# settlement layer's linear binding fold",
        "# (digest = keccak(innerVK ‖ rootC ‖ rangePublicInput), rangePublicInput =",
        "# ZKsyncOSVerifier.computeZKsyncOSHash over the batch public inputs).",
        "# The value covers the ROM image only, so two ELFs that differ outside the",
        "# ROM image share it.",
        "# Serialization: the four ROM root-hash u64 limbs, big-endian, in order.",
    ]


def render_record(
    kind: str,
    derived: str,
    limbs: list[int],
    elf_sha256: str,
    zisk_version: str,
    date: str,
    run_url: str,
    recorded: str | None,
    prior_history: str,
) -> str:
    elf_name = "zksync-os-zisk-guest-aggregator" if kind == "aggregator" else "zksync-os-zisk-guest"
    lines = record_header(kind)
    lines.extend(
        [
            "#",
            f"# Derived with cargo-zisk {zisk_version} on {date} by",
            f"# {run_url}",
            "# from the reproducible container ELF with sha256",
            f"# {elf_sha256}:",
            f"#   cargo-zisk setup -e out/{elf_name} "
            "-k ~/.zisk/provingKey",
            "#",
            f"# Root hash limbs: [{limbs[0]}, {limbs[1]},",
            f"#                   {limbs[2]}, {limbs[3]}]",
            derived,
            "",
        ]
    )
    if recorded is not None:
        lines.extend(
            [
                f"# History: {recorded}",
                f"# (retired {date} by {run_url}).",
            ]
        )
    if prior_history:
        lines.extend([prior_history])
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", choices=("inner", "aggregator"), required=True)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--elf-sha-record", type=Path, required=True)
    parser.add_argument("--verkey", type=Path, required=True)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--zisk-version", required=True)
    parser.add_argument("--date", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--update", action="store_true")
    args = parser.parse_args()

    if VERSION_PATTERN.fullmatch(args.zisk_version) is None:
        raise ValueError("invalid ZiSK version")
    if DATE_PATTERN.fullmatch(args.date) is None:
        raise ValueError("date must use YYYY-MM-DD")
    if RUN_URL_PATTERN.fullmatch(args.run_url) is None:
        raise ValueError("run URL must identify a GitHub Actions run")

    elf_digest = sha256(args.elf)
    recorded_elf_digest = read_recorded_sha256(args.elf_sha_record)
    if elf_digest != recorded_elf_digest:
        raise ValueError(f"{args.elf}: SHA-256 differs from {args.elf_sha_record}")

    limbs, derived = read_verkey(args.verkey)
    source = args.record.read_text()
    recorded = read_active_vk(args.record)
    changed = recorded is None or derived != recorded
    updated = changed and args.update
    if updated:
        args.record.write_text(
            render_record(
                args.kind,
                derived,
                limbs,
                elf_digest,
                args.zisk_version,
                args.date,
                args.run_url,
                recorded,
                history_tail(source),
            )
        )

    metadata = {
        "kind": args.kind,
        "record": str(args.record),
        "elf_sha256": elf_digest,
        "recorded_program_vk": recorded,
        "derived_program_vk": derived,
        "program_vk_limbs": limbs,
        "changed": changed,
        "updated": updated,
    }
    args.metadata.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    if updated:
        state = "rotation proposed"
    elif changed:
        state = "unexpected derivation"
    else:
        state = "pin current"
    print(f"{args.kind}: {state}; ELF {elf_digest}; program VK {derived}")


if __name__ == "__main__":
    main()
