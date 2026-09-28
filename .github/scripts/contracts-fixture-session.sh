#!/usr/bin/env bash
set -euo pipefail
session="${GITHUB_WORKSPACE}/bundle/session"
tools="${GITHUB_WORKSPACE}/bundle/tools"
stack="${GITHUB_WORKSPACE}/docker/zisk-stack"
remote() {
    (cd "$stack" && docker compose -f compose.yaml -f compose.ci.yaml run --rm --no-deps prover \
        cargo-zisk remote --coordinator http://coordinator:7000 "$@")
}
for n in 1 2 3 4; do
    remote prove -e /app/elf/zksync-os-zisk-guest -i "/session/batch-${n}.bin" \
        --timeout 0 -o "/session/vadcop-batch-${n}.bin"
done
"$tools/aggregator_input" -o "$session/agg-input.bin" "$session"/vadcop-batch-{1,2,3,4}.bin \
    2> "$session/aggregator-input.txt"
cat "$session/aggregator-input.txt"
mapfile -t native < <(jq -er '.batches[].native_commitment' "$session/input-manifest.json")
mapfile -t proved < <(grep -oE 'commitment 0x[0-9a-f]{64}' "$session/aggregator-input.txt" | awk '{print $2}')
test "${#native[@]}" -eq 4
test "${#proved[@]}" -eq 4
for i in 0 1 2 3; do
    test "${native[$i]}" = "${proved[$i]}"
    echo "batch $((i+1)): native and proved commitments match: ${proved[$i]}"
done
remote prove -e /app/elf/zksync-os-zisk-guest -i /session/batch-1.bin \
    --timeout 0 -o /session/batch1-plonk.bin --plonk
remote setup -e /app/elf/zksync-os-zisk-guest-aggregator
remote prove -e /app/elf/zksync-os-zisk-guest-aggregator -i /session/agg-input.bin \
    --timeout 0 -o /session/aggregated-plonk.bin --plonk
"$tools/inspect_proof" "$session/batch1-plonk.bin" | tee "$session/batch1-inspect.txt"
"$tools/inspect_proof" "$session/aggregated-plonk.bin" | tee "$session/aggregated-inspect.txt"
record() { sed 's/#.*//' "$1" | tr -d '[:space:]'; }
field() { grep -m1 "^$2" "$1" | sed 's/.*= //'; }
inner="$(record guest/GUEST_PROGRAM_VK)"
aggregator="$(record guest-aggregator/GUEST_PROGRAM_VK)"
root="$(record guest-aggregator/ROOT_C_VADCOP_FINAL)"
test "$(field "$session/batch1-inspect.txt" program_vk)" = "$inner"
test "$(field "$session/aggregated-inspect.txt" program_vk)" = "$aggregator"
for proof in batch1 aggregated; do
    test "$(field "$session/${proof}-inspect.txt" vadcop_vk)" = "$root"
done
test "$(field "$session/batch1-inspect.txt" 'publics\[0..32\]')" = "${proved[0]}"
"$tools/check_binding_digest" "$inner" "$root" "${proved[@]}" | tee "$session/binding-digest.txt"
test "$(field "$session/binding-digest.txt" binding_digest)" = \
    "$(field "$session/aggregated-inspect.txt" 'publics\[0..32\]')"
jq -n --arg sha "$GITHUB_SHA" --arg run "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID" \
    --arg inner "$inner" --arg aggregator "$aggregator" --arg root "$root" \
    --arg inner_elf "$(sha256sum bundle/out/zksync-os-zisk-guest | awk '{print $1}')" \
    --arg aggregator_elf "$(sha256sum bundle/out/zksync-os-zisk-guest-aggregator | awk '{print $1}')" \
    '{selected_sha:$sha,run_url:$run,zisk_version:"1.3.0-alpha",inner_program_vk:$inner,aggregator_program_vk:$aggregator,root_c_vadcop_final:$root,inner_elf_sha256:$inner_elf,aggregator_elf_sha256:$aggregator_elf}' \
    > "$session/session-metadata.json"
echo 'All four native commitments and the aggregate binding digest match.'
