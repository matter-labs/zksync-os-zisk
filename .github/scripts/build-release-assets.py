#!/usr/bin/env python3
"""Build the release verification-key files and identity manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path


MASK64 = (1 << 64) - 1
ROTATIONS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)
VK_PATTERN = re.compile(r"^0x[0-9a-f]{64}$", re.MULTILINE)


def rotate_left(value: int, count: int) -> int:
    if count == 0:
        return value
    return ((value << count) | (value >> (64 - count))) & MASK64


def keccak_f1600(state: list[int]) -> None:
    for constant in ROUND_CONSTANTS:
        columns = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        deltas = [columns[(x - 1) % 5] ^ rotate_left(columns[(x + 1) % 5], 1) for x in range(5)]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= deltas[x]

        moved = [0] * 25
        for y in range(5):
            for x in range(5):
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = rotate_left(
                    state[x + 5 * y], ROTATIONS[x][y]
                )

        for y in range(5):
            for x in range(5):
                state[x + 5 * y] = (
                    moved[x + 5 * y]
                    ^ ((~moved[(x + 1) % 5 + 5 * y]) & moved[(x + 2) % 5 + 5 * y])
                ) & MASK64
        state[0] ^= constant


def keccak256(data: bytes) -> bytes:
    rate = 136
    padding = bytearray(data)
    padding.append(0x01)
    padding.extend(b"\x00" * ((rate - len(padding) % rate) % rate))
    padding[-1] ^= 0x80

    state = [0] * 25
    for offset in range(0, len(padding), rate):
        block = padding[offset : offset + rate]
        for lane in range(rate // 8):
            state[lane] ^= int.from_bytes(block[lane * 8 : lane * 8 + 8], "little")
        keccak_f1600(state)

    return b"".join(lane.to_bytes(8, "little") for lane in state)[:32]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_vk(path: Path) -> tuple[list[int], str]:
    raw = path.read_bytes()
    if len(raw) != 32:
        raise ValueError(f"{path} has {len(raw)} bytes; expected 32")
    limbs = [int.from_bytes(raw[offset : offset + 8], "little") for offset in range(0, 32, 8)]
    canonical = "0x" + b"".join(limb.to_bytes(8, "big") for limb in limbs).hex()
    return limbs, canonical


def read_recorded_vk(path: Path) -> str:
    values = VK_PATTERN.findall(path.read_text())
    if len(values) != 1:
        raise ValueError(f"{path} must contain one active canonical VK")
    return values[0]


def file_entry(source: Path, asset: str) -> dict[str, object]:
    return {
        "asset": asset,
        "sha256": sha256(source),
        "size": source.stat().st_size,
    }


def copy_asset(source: Path, destination: Path) -> dict[str, object]:
    shutil.copy2(source, destination)
    return file_entry(destination, destination.name)


def program_entry(
    elf: dict[str, object],
    verkey: dict[str, object],
    limbs: list[int],
    value: str,
) -> dict[str, object]:
    return {
        "elf": elf,
        "program_vk": value,
        "program_vk_limbs": limbs,
        "verkey": verkey,
    }


def append_summary(path: Path, manifest: dict[str, object]) -> None:
    programs = manifest["programs"]
    inner = programs["inner"]
    aggregator = programs["aggregator"]
    vadcop = manifest["vadcop_final"]
    release = manifest["release"]
    toolchain = manifest["toolchain"]

    def limbs(value: dict[str, object], field: str = "program_vk_limbs") -> str:
        return ", ".join(str(limb) for limb in value[field])

    lines = [
        "## ZiSK release identities",
        "",
        f"Release `{release['tag']}` at `{release['commit']}` with ZiSK "
        f"`{toolchain['zisk_version']}`.",
        "",
        "| Program | ELF SHA-256 | Program VK | Root limbs |",
        "|---|---|---|---|",
        f"| inner | `{inner['elf']['sha256']}` | `{inner['program_vk']}` | "
        f"`[{limbs(inner)}]` |",
        f"| aggregator | `{aggregator['elf']['sha256']}` | "
        f"`{aggregator['program_vk']}` | `[{limbs(aggregator)}]` |",
        f"| vadcop-final | — | `{vadcop['root_c']}` | "
        f"`[{limbs(vadcop, 'root_c_limbs')}]` |",
        "",
        f"ZiSK verification-key hash: `{manifest['zisk_verification_key_hash']}`",
        "",
    ]
    with path.open("a") as stream:
        stream.write("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--zisk-version", required=True)
    parser.add_argument("--inner-elf", type=Path, required=True)
    parser.add_argument("--inner-verkey", type=Path, required=True)
    parser.add_argument("--inner-record", type=Path, required=True)
    parser.add_argument("--aggregator-elf", type=Path, required=True)
    parser.add_argument("--aggregator-verkey", type=Path, required=True)
    parser.add_argument("--aggregator-record", type=Path, required=True)
    parser.add_argument("--vadcop-verkey", type=Path, required=True)
    parser.add_argument("--guest-archive", type=Path, required=True)
    parser.add_argument("--prover-archive", type=Path, required=True)
    parser.add_argument("--prover-service", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()

    if keccak256(b"").hex() != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470":
        raise RuntimeError("Keccak-256 self-test failed")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        raise ValueError("commit must be a full lowercase Git commit ID")

    inner_limbs, inner_vk = read_vk(args.inner_verkey)
    aggregator_limbs, aggregator_vk = read_vk(args.aggregator_verkey)
    vadcop_limbs, vadcop_vk = read_vk(args.vadcop_verkey)

    if inner_vk != read_recorded_vk(args.inner_record):
        raise ValueError("derived inner program VK differs from its release pin")
    if aggregator_vk != read_recorded_vk(args.aggregator_record):
        raise ValueError("derived aggregator program VK differs from its release pin")

    if args.output.exists() and any(args.output.iterdir()):
        raise ValueError(f"output directory is not empty: {args.output}")
    args.output.mkdir(parents=True, exist_ok=True)
    inner_elf = file_entry(args.inner_elf, "zksync-os-zisk-guest")
    aggregator_elf = file_entry(
        args.aggregator_elf, "zksync-os-zisk-guest-aggregator"
    )
    inner_verkey = copy_asset(
        args.inner_verkey, args.output / "zksync-os-zisk-guest.verkey.bin"
    )
    aggregator_verkey = copy_asset(
        args.aggregator_verkey,
        args.output / "zksync-os-zisk-guest-aggregator.verkey.bin",
    )
    vadcop_verkey = copy_asset(
        args.vadcop_verkey, args.output / "zisk-vadcop-final.verkey.bin"
    )

    zisk_vk_hash = "0x" + keccak256(
        bytes.fromhex(inner_vk[2:])
        + bytes.fromhex(aggregator_vk[2:])
        + bytes.fromhex(vadcop_vk[2:])
    ).hex()

    manifest = {
        "schema_version": 1,
        "release": {
            "repository": "matter-labs/zksync-os-zisk",
            "tag": args.tag,
            "commit": args.commit,
        },
        "toolchain": {"zisk_version": args.zisk_version},
        "programs": {
            "inner": program_entry(inner_elf, inner_verkey, inner_limbs, inner_vk),
            "aggregator": program_entry(
                aggregator_elf, aggregator_verkey, aggregator_limbs, aggregator_vk
            ),
        },
        "vadcop_final": {
            "root_c": vadcop_vk,
            "root_c_limbs": vadcop_limbs,
            "verkey": vadcop_verkey,
        },
        "artifacts": {
            "guest_archive": file_entry(args.guest_archive, args.guest_archive.name),
            "prover_archive": file_entry(args.prover_archive, args.prover_archive.name),
            "prover_service": file_entry(
                args.prover_service, "zksync-os-zisk-prover-service"
            ),
        },
        "zisk_verification_key_hash": zisk_vk_hash,
        "zisk_verification_key_hash_preimage": [
            "programs.inner.program_vk",
            "programs.aggregator.program_vk",
            "vadcop_final.root_c",
        ],
    }

    manifest_path = args.output / "zisk-release.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    if args.summary is not None:
        append_summary(args.summary, manifest)

    print(f"inner program VK:      {inner_vk}")
    print(f"aggregator program VK: {aggregator_vk}")
    print(f"vadcop-final root C:    {vadcop_vk}")
    print(f"ZiSK VK hash:           {zisk_vk_hash}")


if __name__ == "__main__":
    main()
