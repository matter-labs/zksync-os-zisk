#!/usr/bin/env bash
# Target-emulation coverage lane for the ZiSK/REVM guest.
#
# Drives ethereum/execution-spec-tests fixtures through zksync-os's
# evm_tester with the rig state-dump hook enabled, converts every dumped
# block into a current-wire BatchInput, and executes each one in ziskemu with
# the pinned ZiSK guest ELF. A guest panic (e.g. an unwired precompile
# crypto hook) is reported per chunk; native-validation failures from the
# reader are reported separately (corpus/reader issues, not guest issues).
#
# Usage:
#   tools/corpus-emu.sh <fixture-path-filter> [...]   # targeted chunks
#   tools/corpus-emu.sh --all                         # every fork/eip dir
#                                                     # in stable+develop
#
# Chunk = one fixture directory filter. Within a chunk evm_tester runs
# with its default rayon parallelism; attribution of a panic is
# chunk + panic message (the message names the failing crypto hook).
# Dump JSONs are deleted after successful conversion to bound disk use.
# Chunks with an existing per-chunk result file are skipped (resume).
#
# Environment (defaults for this workstation):
#   ZKOS_DUMP_WORKTREE  zksync-os checkout with the dump hook
#   ZKOS_FIXTURES       ethereum-fixtures dir (for --all enumeration)
#   ZISK_TESTUTILS_DIR  zksync-os-zisk/tools/test-utils (dump_to_batchinput)
#   ZISK_GUEST_ELF      guest ELF to emulate
#   ZISKEMU             ziskemu binary
#   CORPUS_OUT          work/output directory
#   EMU_JOBS            parallel ziskemu processes (default: nproc)
#   OK_MIN_PERCENT      minimum share of cases the emulator must run OK

set -uo pipefail

ZKOS_DUMP_WORKTREE="${ZKOS_DUMP_WORKTREE:-$HOME/multiprover/zksync-os-dump-v030}"
ZKOS_FIXTURES="${ZKOS_FIXTURES:-$HOME/zksync-os/tests/evm_tester/ethereum-fixtures}"
ZISK_TESTUTILS_DIR="${ZISK_TESTUTILS_DIR:-$HOME/multiprover/zksync-os-zisk/tools/test-utils}"
ZISK_GUEST_ELF="${ZISK_GUEST_ELF:-$HOME/multiprover/zksync-os-zisk/out/zksync-os-zisk-guest}"
ZISKEMU="${ZISKEMU:-$HOME/.zisk-1.2.0-alpha/bin/ziskemu}"
CORPUS_OUT="${CORPUS_OUT:-$HOME/multiprover/corpus-emu-out}"
# ziskemu peaks at ~7 GB RSS per process (measured 2026-07-10); size
# parallelism to MEMORY, not cores — 8-wide OOM-killed this workstation.
AVAIL_GB=$(awk '/MemAvailable/ {print int($2/1048576)}' /proc/meminfo)
EMU_JOBS="${EMU_JOBS:-$(( AVAIL_GB / 9 > 0 ? AVAIL_GB / 9 : 1 ))}"
# Steady state is every case OK bar the handful of documented waivers (26 of
# ~10600), so a floor well above the waiver budget still leaves the verdict
# sensitive to a lane that stops reaching the guest.
OK_MIN_PERCENT="${OK_MIN_PERCENT:-90}"
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-$HOME/.local/zisk-libs/usr/lib/x86_64-linux-gnu:$HOME/.local/zisk-libs/usr/lib/x86_64-linux-gnu/openmpi/lib}"

# Dedicated target dir: the main checkout's cache is in active use by
# other sessions (bisects move HEAD); sharing it races binaries.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/multiprover/zkos-corpus-target}"
export CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_DEV_DEBUG=0
export ZKSYNC_USE_CUDA_STUBS=1
# RUST_MIN_STACK stays UNexported: builds/reader set it per-invocation if
# needed; 256 MB thread stacks must not leak into 8-thread emulators.

[ $# -ge 1 ] || { echo "usage: $0 --all | <fixture-path-filter> [...]"; exit 2; }

mkdir -p "$CORPUS_OUT/chunks"

# Build both tools once; every per-case call uses the binaries directly.
echo "=== building evm-tester and dump_to_batchinput ==="
(cd "$ZKOS_DUMP_WORKTREE/tests/evm_tester" && cargo build --release --bin evm-tester) || exit 1
EVM_TESTER="$CARGO_TARGET_DIR/release/evm-tester"
(cd "$ZISK_TESTUTILS_DIR" && cargo build --release --bin dump_to_batchinput) || exit 1
READER="$CARGO_TARGET_DIR/release/dump_to_batchinput"
[ -x "$EVM_TESTER" ] && [ -x "$READER" ] || { echo "missing built binaries"; exit 1; }
# Snapshot the binaries: later cargo invocations elsewhere must not swap them.
mkdir -p "$CORPUS_OUT/bin"
cp -f "$EVM_TESTER" "$CORPUS_OUT/bin/evm-tester" && EVM_TESTER="$CORPUS_OUT/bin/evm-tester"
cp -f "$READER" "$CORPUS_OUT/bin/dump_to_batchinput" && READER="$CORPUS_OUT/bin/dump_to_batchinput"

# zksync-os's committed indexes disable families its CI skips (unsupported
# precompiles, harness limits). For guest coverage we want every case that
# EXECUTES natively — a user can send any of these txs to a real chain — so
# force-enable everything in the worktree's indexes (worktree-local change).
# The fixture set (13 GB) lives in the main checkout; link it into the
# worktree, where evm_tester resolves it relative to its own directory.
[ -e "$ZKOS_DUMP_WORKTREE/tests/evm_tester/ethereum-fixtures" ] || \
    ln -sfn "$ZKOS_FIXTURES" "$ZKOS_DUMP_WORKTREE/tests/evm_tester/ethereum-fixtures"

if [ "${FORCE_ENABLE_ALL:-1}" = "1" ]; then
    sed -i 's/enabled: false/enabled: true/' \
        "$ZKOS_DUMP_WORKTREE/tests/evm_tester/indexes/"*.yaml
    echo "=== all index entries force-enabled in the worktree ==="
fi

if [ "$1" = "--all" ]; then
    # Every unique <fork>/<eip-or-suite> pair across both channels; the
    # tester's path filter matches identifiers that carry no channel
    # prefix, so one chunk covers a family in stable AND develop at once.
    mapfile -t CHUNKS < <(
        for ch in stable develop; do
            find "$ZKOS_FIXTURES/$ch/state_tests" -mindepth 2 -maxdepth 2 -type d \
                | sed "s|$ZKOS_FIXTURES/$ch/state_tests/||"
        done | sort -u
    )
else
    CHUNKS=("$@")
fi
echo "=== ${#CHUNKS[@]} chunks ==="

emu_one() { # <input.bin> <result-line-prefix> <results-file>
    local input="$1" prefix="$2" results="$3" out rc status detail
    # Hard 10 GB address-space cap per emulator: a pathological input dies
    # alone instead of taking the machine (and every session on it) down.
    out=$(ulimit -v 10485760; nice -n 10 "$ZISKEMU" -e "$ZISK_GUEST_ELF" -i "$input" 2>&1)
    rc=$?
    if [ $rc -ne 0 ] || grep -qi "panicked\|panic at" <<< "$out"; then
        status="PANIC"
        detail=$(grep -im1 "panic" <<< "$out" | tr '\t' ' ' | cut -c1-200)
        [ -n "$detail" ] || detail="exit=$rc: $(tail -1 <<< "$out" | tr '\t' ' ' | cut -c1-160)"
    else
        status="OK"
        detail=$(grep -oE "steps=[0-9]+" <<< "$out" | head -1)
    fi
    echo -e "$prefix\t$status\t$detail" >> "$results"
}
export -f emu_one
export ZISKEMU ZISK_GUEST_ELF LD_LIBRARY_PATH

for FILTER in "${CHUNKS[@]}"; do
    CHUNK=$(echo "$FILTER" | tr '/' '_')
    CHUNK_RESULTS="$CORPUS_OUT/chunks/$CHUNK.tsv"
    if [ -s "$CHUNK_RESULTS" ]; then
        echo "--- [$CHUNK] already done, skipping"
        continue
    fi
    DUMP_DIR="$CORPUS_OUT/dumps/$CHUNK"
    rm -rf "$DUMP_DIR" && mkdir -p "$DUMP_DIR"

    echo "=== [$CHUNK] evm_tester ==="
    (cd "$ZKOS_DUMP_WORKTREE/tests/evm_tester" &&
        ZKOS_STATE_DUMP_DIR="$DUMP_DIR" nice -n 10 "$EVM_TESTER" -p "$FILTER" -t 4 ${EVM_TESTER_ARGS:-}) \
        > "$CORPUS_OUT/chunks/$CHUNK.evm_tester.log" 2>&1
    N_DUMPS=$(ls "$DUMP_DIR" 2>/dev/null | wc -l)
    echo "    evm_tester exit=$? dumps=$N_DUMPS"
    [ "$N_DUMPS" -eq 0 ] && { echo -e "# no dumps" > "$CHUNK_RESULTS"; continue; }

    # Convert dumps -> BatchInputs (serial: fast + disk-friendly), then
    # emulate in parallel.
    TMP_RESULTS=$(mktemp)
    BATCH_DIR="$CORPUS_OUT/batchinputs/$CHUNK"
    mkdir -p "$BATCH_DIR"
    for DUMP in "$DUMP_DIR"/*.json; do
        [ -e "$DUMP" ] || continue
        NAME=$(basename "$DUMP" .json)
        CASE_OUT="$BATCH_DIR/$NAME"
        mkdir -p "$CASE_OUT"
        if (ulimit -v 12582912; nice -n 10 "$READER" "$DUMP" "$CASE_OUT" ${READER_ARGS:-}) > "$CASE_OUT/reader.log" 2>&1 \
                && [ -f "$CASE_OUT/input.bin" ]; then
            rm -f "$DUMP"
        else
            detail=$(grep -im1 -A1 "FAIL\|panicked\|error" "$CASE_OUT/reader.log" | tail -1 | tr '\t' ' ' | cut -c1-200)
            echo -e "$CHUNK\t$NAME\tFAIL\tSKIPPED\t$detail" >> "$TMP_RESULTS"
            # Keep the dump + reader.log of failed conversions for diagnosis.
            mkdir -p "$CORPUS_OUT/failed/$CHUNK"
            mv "$DUMP" "$CORPUS_OUT/failed/$CHUNK/" 2>/dev/null
            mv "$CASE_OUT/reader.log" "$CORPUS_OUT/failed/$CHUNK/$NAME.reader.log" 2>/dev/null
            rm -rf "$CASE_OUT"
        fi
    done

    find "$BATCH_DIR" -name input.bin | \
        xargs -P "$EMU_JOBS" -I{} bash -c \
        'd=$(dirname "{}"); emu_one "{}" "'"$CHUNK"'\t$(basename "$d")\tOK" "'"$TMP_RESULTS"'"'
    mv "$TMP_RESULTS" "$CHUNK_RESULTS"
    rm -rf "$DUMP_DIR"

    awk -F'\t' '{n[$4]++} END {printf "    ["; for (k in n) printf " %s:%d", k, n[k]; print " ]"}' "$CHUNK_RESULTS"
done

# Global summary.
RESULTS="$CORPUS_OUT/results.tsv"
echo -e "chunk\tcase\treader\temulation\tdetail" > "$RESULTS"
cat "$CORPUS_OUT"/chunks/*.tsv 2>/dev/null | grep -v "^#" >> "$RESULTS"
echo
echo "=== SUMMARY ($RESULTS) ==="
awk -F'\t' 'NR>1 {n[$4]++} END {for (k in n) printf "  %-8s %d\n", k, n[k]}' "$RESULTS"
echo
echo "--- panics by detail ---"
awk -F'\t' '$4=="PANIC" {print $5}' "$RESULTS" | sort | uniq -c | sort -rn | head -20

# Waiver reconciliation: every non-OK row must match tools/corpus-waivers.tsv
# (chunk + failure-signature regex, bounded count) or the run FAILS. This is
# what makes steady state machine-checkable: exit 0 == "only the documented
# fixture-artifact waivers remain".
WAIVERS="$(dirname "$0")/corpus-waivers.tsv"
UNEXPECTED_FILE="$CORPUS_OUT/unexpected.txt"
echo
echo "=== WAIVER RECONCILIATION ($WAIVERS) ==="
awk -F'\t' -v wf="$WAIVERS" '
    BEGIN {
        nw = 0
        while ((getline line < wf) > 0) {
            if (line ~ /^#/ || line == "") continue
            split(line, w, "\t")
            wchunk[nw] = w[1]; wmax[nw] = w[2]; wre[nw] = w[3]; wid[nw] = w[4]
            wseen[nw] = 0; nw++
        }
    }
    NR > 1 && $4 != "OK" {
        for (i = 0; i < nw; i++) {
            if ($1 == wchunk[i] && $5 ~ wre[i] && wseen[i] < wmax[i]) {
                wseen[i]++; next
            }
        }
        print "UNEXPECTED: " $0
    }
    END {
        for (i = 0; i < nw; i++)
            printf "  waived %d/%s in %s (%s)\n", wseen[i], wmax[i], wchunk[i], wid[i] > "/dev/stderr"
    }
' "$RESULTS" > "$UNEXPECTED_FILE"
VERDICT=0
# Assert against the FILE: `echo "$big" | grep -q` returns 141 under pipefail,
# because grep exits on its first match and the writer takes SIGPIPE — which
# reads as "no unexpected failures" on exactly the runs that have the most.
if grep -q "^UNEXPECTED:" "$UNEXPECTED_FILE"; then
    echo
    echo "!!! UNEXPECTED FAILURES (not covered by waivers):"
    head -20 "$UNEXPECTED_FILE" | cut -c1-200
    VERDICT=1
fi

# Emulation coverage. The waiver reconciliation counts guest panics, so a run
# where the reader rejected every case reports zero panics and every row waived
# — total failure that reads as success. A run is only meaningful when the guest
# actually executed the corpus, so hold the OK share to a floor.
echo
echo "=== EMULATION COVERAGE (floor ${OK_MIN_PERCENT}% OK) ==="
COVERAGE=$(awk -F'\t' -v floor="$OK_MIN_PERCENT" '
    NR > 1 { total++; if ($4 == "OK") ok++; else if ($4 == "SKIPPED") skipped++ }
    END {
        printf "  %d cases, %d OK, %d skipped (never reached the emulator)\n",
            total, ok, skipped
        if (total == 0)
            print "COVERAGE-FAIL: the run produced no cases at all"
        else if (ok * 100 < total * floor)
            printf "COVERAGE-FAIL: %d/%d OK is under the %d%% floor\n", ok, total, floor
    }
' "$RESULTS")
echo "$COVERAGE"
case "$COVERAGE" in
    *COVERAGE-FAIL*) VERDICT=1 ;;
esac

if [ "$VERDICT" -ne 0 ]; then
    echo "corpus run FAILED: investigate before trusting the guest at this revision."
    exit 1
fi
echo "corpus run PASSED: only documented waivers remain."
