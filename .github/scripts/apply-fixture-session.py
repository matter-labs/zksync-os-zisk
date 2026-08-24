#!/usr/bin/env python3
"""Apply validated fixture-session outputs to their reviewed fixture sites."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path


HEX32 = re.compile(r"^0x[0-9a-f]{64}$")


def replace_once(source: str, pattern: str, replacement: str, label: str) -> str:
    updated, count = re.subn(pattern, replacement, source, count=1, flags=re.DOTALL)
    if count != 1:
        raise ValueError(f"{label}: expected one replacement, found {count}")
    return updated


def unprefixed(value: str, label: str) -> str:
    if HEX32.fullmatch(value) is None:
        raise ValueError(f"{label}: expected one canonical 32-byte hex value")
    return value[2:]


def load_values(path: Path) -> dict:
    values = json.loads(path.read_text())
    if values.get("schema_version") != 1:
        raise ValueError("unsupported fixture-values schema")
    commitments = values.get("proved_commitments")
    trace = values.get("chained_trace")
    if not isinstance(commitments, list) or len(commitments) != 4:
        raise ValueError("expected four proved commitments")
    if not isinstance(trace, list) or len(trace) != 4:
        raise ValueError("expected four chained values")
    for index, value in enumerate(commitments):
        unprefixed(value, f"proved_commitments[{index}]")
    for index, value in enumerate(trace):
        unprefixed(value, f"chained_trace[{index}]")
    for key in ("chained_pi", "binding_digest"):
        unprefixed(values[key], key)
    metadata = values["metadata"]
    for key in ("inner_program_vk", "aggregator_program_vk", "root_c_vadcop_final"):
        unprefixed(metadata[key], key)
    manifest = values["input_manifest"]
    batches = manifest.get("batches")
    if manifest.get("schema_version") != 1 or not isinstance(batches, list) or len(batches) != 4:
        raise ValueError("input manifest must contain four ordered records")
    for index, (record, proved) in enumerate(zip(batches, commitments), 1):
        if (
            record.get("input_filename") != f"batch-{index}.bin"
            or record.get("wire_version") != 3
            or record.get("spec_id") != 1
            or record.get("protocol_version_minor") != 30
            or record.get("native_commitment") != proved
            or re.fullmatch(r"[0-9a-f]{64}", record.get("framed_input_sha256", "")) is None
        ):
            raise ValueError(f"input manifest record {index} is inconsistent")
    if trace[-1] != values["chained_pi"]:
        raise ValueError("final chained trace value differs from chained_pi")
    return values


def update_rust_vector(path: Path, values: dict, include_chained: bool) -> None:
    source = path.read_text()
    metadata = values["metadata"]
    scalar = {
        "INNER_PROGRAM_VK": metadata["inner_program_vk"],
        "ROOT_C_VADCOP_FINAL": metadata["root_c_vadcop_final"],
        "DIGEST": values["binding_digest"],
    }
    if include_chained:
        scalar["CHAINED_PI"] = values["chained_pi"]
    for name, value in scalar.items():
        source = replace_once(
            source,
            rf'(const {name}: &str =\s*)"[0-9a-f]{{64}}"',
            rf'\g<1>"{unprefixed(value, name)}"',
            f"{path}:{name}",
        )
    commitments = ",\n".join(
        f'            "{unprefixed(value, "commitment")}"'
        for value in values["proved_commitments"]
    )
    source = replace_once(
        source,
        r'(const COMMITMENTS: \[&str; 4\] = \[\n).*?(\n\s*\];)',
        rf"\g<1>{commitments},\g<2>",
        f"{path}:COMMITMENTS",
    )
    path.write_text(source)


def render_binding_vector(values: dict) -> str:
    metadata = values["metadata"]
    manifest = values["input_manifest"]
    commitments = values["proved_commitments"]
    trace = values["chained_trace"]
    date = metadata["session_date"]
    run_url = metadata["run_url"]
    inputs = "\n".join(
        f"- `{record['input_filename']}`: framed SHA-256 `{record['framed_input_sha256']}`"
        for record in manifest["batches"]
    )
    commitment_lines = "\n".join(
        f"commitment_{index} = {value}" for index, value in enumerate(commitments, 1)
    )
    pi_lines = "\n".join(
        f"PI[{index}] = 0x00000000{unprefixed(value, 'commitment')[:56]}"
        for index, value in enumerate(commitments)
    )
    trace_lines = [f"seed (= PI[0]) = {trace[0]}"]
    trace_lines.extend(f"after PI[{index}]    = {trace[index]}" for index in range(1, 4))
    return f"""## Inputs (real 4-batch aggregation session, ZiSK v0.18.0, {date})

This vector was produced by [fixture-session run]({run_url}) from
`{metadata['selected_ref']}` at `{metadata['selected_sha']}`, after multi-wire
support landed on `main`. The inputs are intentionally frozen wire-v3
AtlasV2 fixtures (wire version 3, spec ID 1, protocol minor 30), encoded by
`tools/test-utils` and executed natively through the version-dispatching
bincode entry point. The proofs use the current guest ELF and current inner
programVK; accepting the historical input format does not preserve the old
programVK.

Native commitments from `input-manifest.json` were automatically compared,
in batch order, with the commitments extracted from all four guest proofs
before PLONK wrapping or recursive proving. All four pairs were equal.

Session data: inner ELF SHA-256
`{metadata['inner_elf_sha256']}`, aggregator ELF SHA-256
`{metadata['aggregator_elf_sha256']}`.

Framed inputs:

{inputs}

```text
innerProgramVK   = {metadata['inner_program_vk']}
rootCVadcopFinal = {metadata['root_c_vadcop_final']}
```

Batch commitments, in order:

```text
{commitment_lines}
```

## Chain trace

Per-batch public inputs (`commitment >> 32`):

```text
{pi_lines}
```

Accumulator after each step:

```text
{chr(10).join(trace_lines)}
```

## Pinned outputs

```text
chainedPI = {values['chained_pi']}
digest    = {values['binding_digest']}
```

The real aggregated proof of this range commits the same digest: the
PLONK-wrapped aggregate has wire public-values bytes `[32..64]` equal to
`digest`, bytes `[0..32]` equal to the aggregator programVK
`{metadata['aggregator_program_vk']}`, and bytes `[288..320]` equal to
`rootCVadcopFinal`.

The fixture publisher automatically updates this document,
`guest-aggregator/src/lib.rs`, `prover/tests/real_aggregation_vector.rs`, and
`prover/tests/data/real_vadcop_final_zisk_v0.18.0.bin` in a separate PR.
"""


def update_repository(root: Path, values: dict, vadcop: Path) -> None:
    doc = root / "guest-aggregator/BINDING_VECTOR.md"
    source = doc.read_text()
    prefix = source.split("## Inputs", 1)[0]
    if prefix == source:
        raise ValueError(f"{doc}: missing Inputs section")
    doc.write_text(prefix + render_binding_vector(values))

    update_rust_vector(root / "guest-aggregator/src/lib.rs", values, include_chained=True)
    update_rust_vector(
        root / "prover/tests/real_aggregation_vector.rs", values, include_chained=False
    )
    destination = root / "prover/tests/data/real_vadcop_final_zisk_v0.18.0.bin"
    if not vadcop.is_file() or vadcop.stat().st_size == 0:
        raise ValueError(f"{vadcop}: missing vadcop_final fixture")
    shutil.copyfile(vadcop, destination)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--values", type=Path, required=True)
    parser.add_argument("--vadcop", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args()
    values = load_values(args.values)
    update_repository(args.repo_root, values, args.vadcop)


if __name__ == "__main__":
    main()
