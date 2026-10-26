#!/usr/bin/env bash

set -euo pipefail

readonly AGENTSCM_REVISION=24b70c0796e8288d1560adda36a1590e613d0ffc
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly SCRIPT_DIR
readonly PATCH_FILE="$SCRIPT_DIR/agentscm-rnqc.patch"

if [[ $# -ne 2 ]]; then
  echo "usage: $0 AGENTSCM_SOURCE OUTPUT_BINARY" >&2
  exit 2
fi

readonly SOURCE_DIR=$1
readonly OUTPUT_BINARY=$2

head_revision=$(git -C "$SOURCE_DIR" rev-parse --verify 'HEAD^{commit}')
if [[ $head_revision != "$AGENTSCM_REVISION" ]]; then
  echo "AgentSCM source must be exactly $AGENTSCM_REVISION" >&2
  exit 1
fi

build_dir=$(mktemp -d "${TMPDIR:-/tmp}/rnqc-agentscm.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT

git -C "$SOURCE_DIR" archive "$AGENTSCM_REVISION" | tar -x -C "$build_dir"
git -C "$build_dir" apply --check "$PATCH_FILE"
git -C "$build_dir" apply "$PATCH_FILE"

target_dir=${CARGO_TARGET_DIR:-$build_dir/target}
(cd "$build_dir" && cargo build --locked --release --bin agentscm)
mkdir -p "$(dirname -- "$OUTPUT_BINARY")"
install -m 0755 "$target_dir/release/agentscm" "$OUTPUT_BINARY"

"$OUTPUT_BINARY" local-validation --help >/dev/null
printf 'Built RNQC AgentSCM %s compatibility binary at %s\n' "$AGENTSCM_REVISION" "$OUTPUT_BINARY"
