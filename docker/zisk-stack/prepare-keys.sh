#!/usr/bin/env bash
# zisk-prepare-keys: fetch, verify and install the ZiSK proving keys into the
# worker's key volume, then generate the constant-tree files, the way ziskup
# does for a host install. Runs as a one-shot container before the worker.
#
# Idempotent: a marker file records the installed version and the tarball
# digests, and a marker for the current ZISK_VERSION makes the run a no-op.
#
# Sources and verification:
#   - Tarballs come from Polygon's public bucket (ZISK_SETUP_BUCKET_URL). The
#     bucket publishes md5 sidecars; those are checked.
#   - Each tarball is also checked against the sha256 pin in
#     ZISK_KEYS_SHA256_FILE. A PENDING pin is accepted only with
#     ZISK_KEYS_ALLOW_UNPINNED=1; the observed digest is then printed so it
#     can be recorded.
#
# Environment (all optional unless noted):
#   ZISK_VERSION             toolchain version; the image sets it (required)
#   ZISK_KEYS_DIR            key volume mount point        (/opt/zisk/keys)
#   ZISK_SETUP_BUCKET_URL    tarball source                (Polygon's bucket)
#   ZISK_KEYS_SHA256_FILE    pin file                      (/opt/zisk/keys.sha256)
#   ZISK_KEYS_ALLOW_UNPINNED accept PENDING pins           (0)
#   ZISK_KEYS_GPU            pass --gpu to check-setup     (1)
#   ZISK_KEYS_OWNER          chown target when run as root (zisk:zisk)
#   ZISK_KEYS_FORCE          reinstall even if the marker matches (0)
#   ZISK_KEYS_MIN_FREE_GB    free-space floor before downloading (70)
set -euo pipefail

: "${ZISK_VERSION:?ZISK_VERSION must be set (the worker image sets it)}"
KEYS_DIR="${ZISK_KEYS_DIR:-/opt/zisk/keys}"
BUCKET_URL="${ZISK_SETUP_BUCKET_URL:-https://storage.googleapis.com/zisk-setup}"
PINS_FILE="${ZISK_KEYS_SHA256_FILE:-/opt/zisk/keys.sha256}"
ALLOW_UNPINNED="${ZISK_KEYS_ALLOW_UNPINNED:-0}"
USE_GPU="${ZISK_KEYS_GPU:-1}"
OWNER="${ZISK_KEYS_OWNER:-zisk:zisk}"
FORCE="${ZISK_KEYS_FORCE:-0}"
MIN_FREE_GB="${ZISK_KEYS_MIN_FREE_GB:-70}"
CARGO_ZISK_DEV="${CARGO_ZISK_DEV:-/opt/zisk/bin/cargo-zisk-dev}"

MARKER="${KEYS_DIR}/.zisk-keys-ready"
DOWNLOAD_DIR="${KEYS_DIR}/.download"
STARK_TARBALL="zisk-provingkey-${ZISK_VERSION}.tar.gz"
PLONK_TARBALL="zisk-provingkey-plonk-${ZISK_VERSION}.tar.gz"

log() { printf '[zisk-prepare-keys] %s\n' "$*"; }
die() { printf '[zisk-prepare-keys] ERROR: %s\n' "$*" >&2; exit 1; }

# Print the pinned digest for a tarball name: a hex digest, PENDING, or
# nothing when the file has no line for it.
pinned_sha256() {
    [[ -f "$PINS_FILE" ]] || return 0
    awk -v f="$1" '$1 !~ /^#/ && $2 == f { print $1; exit }' "$PINS_FILE"
}

fetch() {
    # Resumable, so an interrupted 22 GB download continues instead of
    # restarting; --retry-all-errors covers transient HTTP failures.
    curl -fL --retry 5 --retry-all-errors -C - -o "$2" "$1"
}

# Download, verify (md5 sidecar and sha256 pin), and extract one tarball.
# Prints the observed sha256 on stdout; logs go to stderr.
install_tarball() {
    local name="$1" subdir="$2"
    local tarball="${DOWNLOAD_DIR}/${name}" pin actual
    pin="$(pinned_sha256 "$name")"
    if [[ -z "$pin" || "$pin" == "PENDING" ]]; then
        if [[ "$ALLOW_UNPINNED" != "1" ]]; then
            die "no sha256 pin for ${name} in ${PINS_FILE}. Set ZISK_KEYS_ALLOW_UNPINNED=1 to accept the bucket's md5 alone; the run then prints the digest to record."
        fi
        log "WARNING: ${name} has no sha256 pin; the bucket md5 is the only integrity check" >&2
    fi

    log "downloading ${name} (this is large; the download resumes if interrupted)" >&2
    fetch "${BUCKET_URL}/${name}" "$tarball"
    fetch "${BUCKET_URL}/${name}.md5" "${tarball}.md5"
    (cd "$DOWNLOAD_DIR" && md5sum -c --quiet "${name}.md5" >&2) || die "md5 mismatch for ${name}"
    log "md5 OK for ${name}" >&2

    actual="$(sha256sum "$tarball" | cut -d' ' -f1)"
    if [[ -n "$pin" && "$pin" != "PENDING" ]]; then
        [[ "$actual" == "$pin" ]] || die "sha256 mismatch for ${name}: pinned ${pin}, got ${actual}"
        log "sha256 OK for ${name}" >&2
    else
        log "RECORD THIS PIN in keys.sha256: ${actual}  ${name}" >&2
    fi

    log "extracting ${name} into ${KEYS_DIR}/${subdir}" >&2
    rm -rf "${KEYS_DIR:?}/${subdir}"
    tar --no-same-owner -xzf "$tarball" -C "$KEYS_DIR"
    [[ -d "${KEYS_DIR}/${subdir}" ]] || die "${name} did not produce ${subdir}/"
    rm -f "$tarball" "${tarball}.md5"
    printf '%s\n' "$actual"
}

main() {
    mkdir -p "$KEYS_DIR"
    if [[ "$FORCE" != "1" && -f "$MARKER" ]] && grep -qx "version=${ZISK_VERSION}" "$MARKER"; then
        log "keys for ZiSK ${ZISK_VERSION} already installed in ${KEYS_DIR}; nothing to do"
        cat "$MARKER"
        exit 0
    fi

    command -v curl >/dev/null || die "curl is required"
    [[ -x "$CARGO_ZISK_DEV" ]] || die "${CARGO_ZISK_DEV} not found; run this inside the worker image"

    local free_gb
    free_gb="$(df -Pk "$KEYS_DIR" | awk 'NR==2 { printf "%d", $4 / 1024 / 1024 }')"
    if (( free_gb < MIN_FREE_GB )); then
        die "${KEYS_DIR} has ${free_gb} GB free; the keys need about ${MIN_FREE_GB} GB during installation (26 GB of tarballs plus the unpacked keys). Set ZISK_KEYS_MIN_FREE_GB to override."
    fi

    log "installing ZiSK ${ZISK_VERSION} proving keys into ${KEYS_DIR} (${free_gb} GB free)"
    rm -f "$MARKER"
    mkdir -p "$DOWNLOAD_DIR"

    local stark_sha plonk_sha
    stark_sha="$(install_tarball "$STARK_TARBALL" provingKey)"
    plonk_sha="$(install_tarball "$PLONK_TARBALL" provingKeySnark)"
    rmdir "$DOWNLOAD_DIR" 2>/dev/null || true

    # Constant-tree generation, as ziskup runs it after installing the STARK
    # key. The GPU build of cargo-zisk-dev needs the driver library even for
    # this step, so the container must have the GPU attached.
    log "generating constant-tree files (cargo-zisk-dev check-setup); this takes a while"
    local check_args=(check-setup --proving-key "${KEYS_DIR}/provingKey" -a)
    [[ "$USE_GPU" == "1" ]] && check_args+=(--gpu)
    "$CARGO_ZISK_DEV" "${check_args[@]}"

    # The worker writes generated artefacts next to the keys at run time, so
    # the tree must be writable by the worker user.
    if [[ "$(id -u)" -eq 0 ]]; then
        chown -R "$OWNER" "$KEYS_DIR"
    fi
    chmod -R u+rwX,g+rwX,o-rwx "$KEYS_DIR"

    {
        echo "version=${ZISK_VERSION}"
        echo "stark_tarball=${STARK_TARBALL}"
        echo "stark_sha256=${stark_sha}"
        echo "plonk_tarball=${PLONK_TARBALL}"
        echo "plonk_sha256=${plonk_sha}"
        echo "completed=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$MARKER"
    log "done"
    cat "$MARKER"
}

main "$@"
