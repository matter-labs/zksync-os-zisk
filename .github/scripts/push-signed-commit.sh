#!/usr/bin/env bash
set -euo pipefail

# Point a branch at one new commit that GitHub signs. `main` requires signed
# commits; a `git push` of a local commit is unsigned, but GitHub signs the
# commits a GitHub App installation token creates through the REST API, as the
# org's release-please workflow relies on. The commit is built on BASE through
# the Git Data API, so TARGET moves to it in one ref update.
#
# Usage: push-signed-commit.sh TARGET BASE MESSAGE_FILE EXPECTED_OLD PATH...
#   TARGET        branch to create or move to the new commit
#   BASE          parent of the new commit
#   MESSAGE_FILE  commit message
#   EXPECTED_OLD  TARGET's current commit, or "" when TARGET must not exist yet
#   PATH...       repository paths, read from the working tree; a path that does
#                 not exist there is deleted
#
# Required environment: GH_TOKEN (a GitHub App installation token),
# GITHUB_REPOSITORY. Prints the new commit.

: "${GH_TOKEN:?}" "${GITHUB_REPOSITORY:?}"
if (( $# < 5 )); then
    echo "usage: $0 TARGET BASE MESSAGE_FILE EXPECTED_OLD PATH..." >&2
    exit 2
fi
target="$1"
base="$2"
message_file="$3"
expected_old="$4"
shift 4

repo="repos/${GITHUB_REPOSITORY}"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

current_sha() {
    gh api "${repo}/git/matching-refs/heads/$1" \
        --jq ".[] | select(.ref == \"refs/heads/$1\") | .object.sha"
}

echo '[]' > "${work}/tree.json"
for path in "$@"; do
    if [[ -z "${path}" ]]; then
        echo "ERROR: empty path" >&2
        exit 2
    fi
    if [[ -f "${path}" ]]; then
        mode=100644
        [[ -x "${path}" ]] && mode=100755
        base64 < "${path}" | tr -d '\n' > "${work}/contents"
        jq -n --rawfile content "${work}/contents" '{content: $content, encoding: "base64"}' \
            > "${work}/blob.json"
        sha="$(gh api "${repo}/git/blobs" --input "${work}/blob.json" --jq .sha)"
        jq --arg path "${path}" --arg mode "${mode}" --arg sha "${sha}" \
            '. + [{path: $path, mode: $mode, type: "blob", sha: $sha}]' \
            "${work}/tree.json" > "${work}/next.json"
    else
        # A null sha removes the path from the base tree.
        jq --arg path "${path}" '. + [{path: $path, mode: "100644", type: "blob", sha: null}]' \
            "${work}/tree.json" > "${work}/next.json"
    fi
    mv "${work}/next.json" "${work}/tree.json"
done

base_tree="$(gh api "${repo}/git/commits/${base}" --jq .tree.sha)"
jq -n --arg base_tree "${base_tree}" --slurpfile tree "${work}/tree.json" \
    '{base_tree: $base_tree, tree: $tree[0]}' > "${work}/tree-request.json"
tree="$(gh api "${repo}/git/trees" --input "${work}/tree-request.json" --jq .sha)"

jq -n --rawfile message "${message_file}" --arg tree "${tree}" --arg base "${base}" \
    '{message: $message, tree: $tree, parents: [$base]}' > "${work}/commit-request.json"
commit="$(gh api "${repo}/git/commits" --input "${work}/commit-request.json" --jq .sha)"

verified="$(gh api "${repo}/commits/${commit}" --jq '.commit.verification.verified')"
if [[ "${verified}" != true ]]; then
    echo "ERROR: GitHub did not sign ${commit}; GH_TOKEN must be an App installation token" >&2
    exit 1
fi

# The check and the ref update are two API calls, so a push to TARGET between
# them is overwritten; the callers own TARGET.
current="$(current_sha "${target}")"
if [[ "${current}" != "${expected_old}" ]]; then
    echo "ERROR: ${target} is at '${current}', expected '${expected_old}'" >&2
    exit 1
fi
if [[ -z "${current}" ]]; then
    gh api --method POST "${repo}/git/refs" \
        -f ref="refs/heads/${target}" -f sha="${commit}" >/dev/null
else
    gh api --method PATCH "${repo}/git/refs/heads/${target}" \
        -f sha="${commit}" -F force=true >/dev/null
fi
echo "${commit}"
