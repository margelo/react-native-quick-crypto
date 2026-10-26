#!/usr/bin/env bash

set -euo pipefail

readonly AGENTSCM_REVISION=24b70c0796e8288d1560adda36a1590e613d0ffc
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly SCRIPT_DIR
readonly PATCH_FILE="$SCRIPT_DIR/agentscm-rnqc.patch"

if [[ $# -ne 1 ]]; then
  echo "usage: $0 AGENTSCM_SOURCE" >&2
  exit 2
fi

readonly SOURCE_DIR=$1
head_revision=$(git -C "$SOURCE_DIR" rev-parse --verify 'HEAD^{commit}')
[[ $head_revision == "$AGENTSCM_REVISION" ]] || {
  echo "AgentSCM source must be exactly $AGENTSCM_REVISION" >&2
  exit 1
}

test_dir=$(mktemp -d "${TMPDIR:-/tmp}/rnqc-agentscm-tests.XXXXXX")
cleanup() {
  case $test_dir in
    "${TMPDIR:-/tmp}"/rnqc-agentscm-tests.*) rm -rf -- "$test_dir" ;;
    *) echo "refusing to remove unexpected test path: $test_dir" >&2 ;;
  esac
}
trap cleanup EXIT

git -C "$SOURCE_DIR" archive "$AGENTSCM_REVISION" | tar -x -C "$test_dir"
git -C "$test_dir" apply --check "$PATCH_FILE"
git -C "$test_dir" apply "$PATCH_FILE"
(cd "$test_dir" && cargo test --locked --test local_validation --test local_validation_cli)
