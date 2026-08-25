#!/usr/bin/env bash
set -euo pipefail

# Prove a four-batch ZiSK fixture session on a GPU box. The inputs are
# wire-v5 protocol-v32 AtlasV4 batches, while both proofs use the current
# repository ELFs and canonical programVK pins in session-metadata.json.
#
# Required environment:
#   CARGO_ZISK, GUEST_ELF, AGG_ELF, ZISK_PK, ZISK_SK, TOOLS_DIR, SESSION_DIR

: "${CARGO_ZISK:?}" "${GUEST_ELF:?}" "${AGG_ELF:?}" "${ZISK_PK:?}" "${ZISK_SK:?}"
: "${TOOLS_DIR:?}" "${SESSION_DIR:?}"

metadata="${SESSION_DIR}/session-metadata.json"
manifest="${SESSION_DIR}/input-manifest.json"
test -f "${metadata}"
test -f "${manifest}"

inner_program_vk="$(jq -er '.inner_program_vk' "${metadata}")"
aggregator_program_vk="$(jq -er '.aggregator_program_vk' "${metadata}")"
root_c_vadcop_final="$(jq -er '.root_c_vadcop_final' "${metadata}")"
selected_ref="$(jq -er '.selected_ref' "${metadata}")"
selected_sha="$(jq -er '.selected_sha' "${metadata}")"
inner_elf_sha256="$(jq -er '.inner_elf_sha256' "${metadata}")"
aggregator_elf_sha256="$(jq -er '.aggregator_elf_sha256' "${metadata}")"
zisk_version="$(jq -er '.zisk_version' "${metadata}")"

check() {
    local what="$1" got="$2" want="$3"
    if [[ "${got}" != "${want}" ]]; then
        echo "ERROR: ${what}: ${got} != ${want}" >&2
        exit 1
    fi
    echo "OK: ${what} = ${got}"
}

field() {
    grep -m1 "^$2" "$1" | sed 's/.*= //'
}

vk_of_setup_dir() {
    python3 - "$1" <<'PY'
import glob
import struct
import sys

files = glob.glob(sys.argv[1] + "/*.verkey.bin")
if len(files) != 1:
    raise SystemExit(f"expected one verkey.bin, found {files}")
raw = open(files[0], "rb").read()
if len(raw) != 32:
    raise SystemExit(f"{files[0]} has {len(raw)} bytes; expected 32")
limbs = struct.unpack("<4Q", raw)
print("0x" + b"".join(limb.to_bytes(8, "big") for limb in limbs).hex())
PY
}

vk_limbs() {
    python3 - "$1" <<'PY'
import sys

raw = bytes.fromhex(sys.argv[1].removeprefix("0x"))
if len(raw) != 32:
    raise SystemExit("programVK/root must contain 32 bytes")
print(", ".join(str(int.from_bytes(raw[i:i + 8], "big")) for i in range(0, 32, 8)))
PY
}

calibrate() {
    local name="$1" elf="$2" expected="$3"
    local setup_dir="${SESSION_DIR}/setup-${name}"
    mkdir -p "${setup_dir}"
    "${CARGO_ZISK}" program-setup -e "${elf}" -k "${ZISK_PK}" -g -o "${setup_dir}"
    local derived
    derived="$(vk_of_setup_dir "${setup_dir}")"
    check "${name} programVK calibration" "${derived}" "${expected}"
}

check "inner ELF SHA-256 in GPU bundle" \
    "$(sha256sum "${GUEST_ELF}" | awk '{print $1}')" "${inner_elf_sha256}"
check "aggregator ELF SHA-256 in GPU bundle" \
    "$(sha256sum "${AGG_ELF}" | awk '{print $1}')" "${aggregator_elf_sha256}"

cargo_zisk_version="$("${CARGO_ZISK}" --version | head -n 1)"
echo "cargo-zisk executed: ${cargo_zisk_version}"

echo "==> calibration: both programVKs must reproduce the repository pins"
calibrate inner "${GUEST_ELF}" "${inner_program_vk}"
calibrate aggregator "${AGG_ELF}" "${aggregator_program_vk}"

echo "==> proving the four per-batch vadcop_final streams"
for n in 1 2 3 4; do
    "${CARGO_ZISK}" prove -e "${GUEST_ELF}" -i "${SESSION_DIR}/batch-${n}.bin" \
        -k "${ZISK_PK}" -y -o "${SESSION_DIR}/vadcop-batch-${n}.bin" -g --emulator
done

echo "==> extracting and comparing proved commitments before PLONK/aggregation"
# aggregator_input validates each raw stream and reports its commitment in the
# exact batch order supplied. Assembly is local preparation only; no recursive
# proof or PLONK wrap is started until the comparisons below all pass.
"${TOOLS_DIR}/aggregator_input" -o "${SESSION_DIR}/agg-input.bin" \
    "${SESSION_DIR}"/vadcop-batch-{1,2,3,4}.bin 2> "${SESSION_DIR}/aggregator-input.txt"
cat "${SESSION_DIR}/aggregator-input.txt"

jq -e '
    .schema_version == 1 and
    (.batches | length == 4) and
    all(.batches[];
        .wire_version == 5 and .spec_id == 3 and
        .protocol_version_minor == 32 and
        (.input_filename | test("^batch-[1-4]\\.bin$")) and
        (.framed_input_sha256 | test("^[0-9a-f]{64}$")) and
        (.native_commitment | test("^0x[0-9a-f]{64}$")))
' "${manifest}" >/dev/null

mapfile -t native_commitments < <(jq -er '.batches[].native_commitment' "${manifest}")
mapfile -t proved_commitments < <(
    grep -oE 'commitment 0x[0-9a-f]{64}' "${SESSION_DIR}/aggregator-input.txt" | awk '{print $2}'
)
if [[ "${#native_commitments[@]}" -ne 4 || "${#proved_commitments[@]}" -ne 4 ]]; then
    echo "ERROR: expected four native and four proved commitments" >&2
    exit 1
fi
if printf '%s\n' "${proved_commitments[@]}" | grep -qx \
    '0x0000000000000000000000000000000000000000000000000000000000000000'; then
    echo "ERROR: proved commitment is zero" >&2
    exit 1
fi
if [[ "$(printf '%s\n' "${proved_commitments[@]}" | sort -u | wc -l | tr -d ' ')" -ne 4 ]]; then
    echo "ERROR: proved commitments are not distinct" >&2
    exit 1
fi

comparison="${SESSION_DIR}/commitment-comparison.txt"
: > "${comparison}"
for index in 0 1 2 3; do
    batch=$((index + 1))
    check "batch ${batch} native/proved commitment" \
        "${proved_commitments[$index]}" "${native_commitments[$index]}" | tee -a "${comparison}"
done

check "aggregator input inner programVK" \
    "$(grep -m1 'inner programVK' "${SESSION_DIR}/aggregator-input.txt" | awk '{print $NF}')" \
    "${inner_program_vk}"
check "aggregator input rootCVadcopFinal" \
    "$(grep -m1 'vadcopVK' "${SESSION_DIR}/aggregator-input.txt" | awk '{print $NF}')" \
    "${root_c_vadcop_final}"

echo "==> PLONK-wrapping batch 1"
"${CARGO_ZISK}" prove -e "${GUEST_ELF}" -i "${SESSION_DIR}/batch-1.bin" \
    -k "${ZISK_PK}" -w "${ZISK_SK}" --plonk -y \
    -o "${SESSION_DIR}/batch1-plonk.bin" -g --emulator

echo "==> proving and PLONK-wrapping the aggregation"
"${CARGO_ZISK}" prove -e "${AGG_ELF}" -i "${SESSION_DIR}/agg-input.bin" \
    -k "${ZISK_PK}" -w "${ZISK_SK}" --plonk -y \
    -o "${SESSION_DIR}/aggregated-plonk.bin" -g --emulator

echo "==> extracting the wire fixtures"
"${TOOLS_DIR}/inspect_proof" "${SESSION_DIR}/batch1-plonk.bin" \
    | tee "${SESSION_DIR}/batch1-inspect.txt"
"${TOOLS_DIR}/inspect_proof" "${SESSION_DIR}/aggregated-plonk.bin" \
    | tee "${SESSION_DIR}/aggregated-inspect.txt"

echo "==> checking proof pins and commitments"
check "batch fixture inner programVK" \
    "$(field "${SESSION_DIR}/batch1-inspect.txt" program_vk)" "${inner_program_vk}"
check "batch fixture rootCVadcopFinal" \
    "$(field "${SESSION_DIR}/batch1-inspect.txt" vadcop_vk)" "${root_c_vadcop_final}"
check "batch fixture commitment" \
    "$(field "${SESSION_DIR}/batch1-inspect.txt" 'publics\[0..32\]')" \
    "${proved_commitments[0]}"
check "aggregated fixture aggregator programVK" \
    "$(field "${SESSION_DIR}/aggregated-inspect.txt" program_vk)" "${aggregator_program_vk}"
check "aggregated fixture rootCVadcopFinal" \
    "$(field "${SESSION_DIR}/aggregated-inspect.txt" vadcop_vk)" "${root_c_vadcop_final}"

echo "==> independently recomputing the binding digest"
"${TOOLS_DIR}/check_binding_digest" "${inner_program_vk}" "${root_c_vadcop_final}" \
    "${proved_commitments[@]}" | tee "${SESSION_DIR}/binding-digest.txt"
range_public_input="$(field "${SESSION_DIR}/binding-digest.txt" range_public_input)"
binding_digest="$(field "${SESSION_DIR}/binding-digest.txt" binding_digest)"
check "binding digest (independent fold)" "${binding_digest}" \
    "$(field "${SESSION_DIR}/aggregated-inspect.txt" 'publics\[0..32\]')"

jq -n \
    --slurpfile metadata "${metadata}" \
    --slurpfile input_manifest "${manifest}" \
    --arg cargo_zisk_version "${cargo_zisk_version}" \
    --arg c1 "${proved_commitments[0]}" \
    --arg c2 "${proved_commitments[1]}" \
    --arg c3 "${proved_commitments[2]}" \
    --arg c4 "${proved_commitments[3]}" \
    --arg range_public_input "${range_public_input}" \
    --arg binding_digest "${binding_digest}" \
    '{
        schema_version: 1,
        metadata: $metadata[0],
        input_manifest: $input_manifest[0],
        cargo_zisk_version: $cargo_zisk_version,
        proved_commitments: [$c1, $c2, $c3, $c4],
        range_public_input: $range_public_input,
        binding_digest: $binding_digest,
        repository_updates: [
            "guest-aggregator/BINDING_VECTOR.md",
            "guest-aggregator/src/lib.rs",
            "prover/tests/real_aggregation_vector.rs",
            "prover/tests/data/real_vadcop_final_zisk_v0.18.0.bin"
        ]
    }' > "${SESSION_DIR}/fixture-values.json"

inner_limbs="$(vk_limbs "${inner_program_vk}")"
aggregator_limbs="$(vk_limbs "${aggregator_program_vk}")"
root_limbs="$(vk_limbs "${root_c_vadcop_final}")"

echo "==> writing SUMMARY.md"
{
    echo "# ZiSK fixture session"
    echo
    echo "| Build/prover fact | Value |"
    echo "|---|---|"
    echo "| Selected ref | \`${selected_ref}\` |"
    echo "| Selected commit | \`${selected_sha}\` |"
    echo "| ZiSK install pin | \`${zisk_version}\` |"
    echo "| cargo-zisk executed | \`${cargo_zisk_version}\` |"
    echo "| Inner ELF SHA-256 | \`${inner_elf_sha256}\` |"
    echo "| Aggregator ELF SHA-256 | \`${aggregator_elf_sha256}\` |"
    echo
    echo "| Verification value | Hex | Four u64 limbs |"
    echo "|---|---|---|"
    echo "| inner programVK | \`${inner_program_vk}\` | \`[${inner_limbs}]\` |"
    echo "| aggregator programVK | \`${aggregator_program_vk}\` | \`[${aggregator_limbs}]\` |"
    echo "| rootCVadcopFinal | \`${root_c_vadcop_final}\` | \`[${root_limbs}]\` |"
    echo
    echo "Inputs are deterministic wire-v5 protocol-v32 AtlasV4 fixtures: wire"
    echo "version \`5\`, spec ID \`3\`, protocol minor \`32\`. They carry the"
    echo "four-word public-input shape used by the current settlement contracts and"
    echo "are proved by the current inner guest ELF and inner programVK above."
    echo
    echo "| Input | Framed SHA-256 | Native commitment | Proved commitment | Result |"
    echo "|---|---|---|---|---|"
    for index in 0 1 2 3; do
        filename="$(jq -r ".batches[${index}].input_filename" "${manifest}")"
        framed_hash="$(jq -r ".batches[${index}].framed_input_sha256" "${manifest}")"
        echo "| \`${filename}\` | \`${framed_hash}\` | \`${native_commitments[$index]}\` | \`${proved_commitments[$index]}\` | equal |"
    done
    echo
    echo "Range public input: \`${range_public_input}\`"
    echo
    echo "Final binding digest: \`${binding_digest}\`"
    echo
    echo "## Publication"
    echo
    echo "The publisher opens or updates a separate in-repository fixture PR with:"
    echo
    jq -r '.repository_updates[] | "- `" + . + "`"' "${SESSION_DIR}/fixture-values.json"
} > "${SESSION_DIR}/SUMMARY.md"

echo "session complete: ${SESSION_DIR}/SUMMARY.md"
