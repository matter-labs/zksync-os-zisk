#!/usr/bin/env bash
# zisk-worker-entrypoint: make sure the proving keys are installed, then run
# the worker in this process.
#
# `zisk-prepare-keys` is a no-op once its marker for the image's ZISK_VERSION
# exists, so a restarted worker starts at once. A fresh key volume costs the
# 27 GB download and the constant-tree generation first; the worker is not
# registered with the coordinator until then, and the prover daemon retries
# its setup until it is. The key-preparation knobs (ZISK_KEYS_*,
# ZISK_SETUP_BUCKET_URL) are read from the environment as usual.
#
# Runs as the image's `zisk` user, so the key volume's root must be writable
# by it: Docker gives a fresh named volume the image directory's ownership,
# a k8s local-path volume is world-writable, and other provisioners take the
# pod's fsGroup.
set -euo pipefail

zisk-prepare-keys
exec zisk-worker "$@"
