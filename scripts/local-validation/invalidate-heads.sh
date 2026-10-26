#!/usr/bin/env bash

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${REPO:?REPO is required}"
: "${DEFAULT_BRANCH:?DEFAULT_BRANCH is required}"
: "${RUN_URL:?RUN_URL is required}"

work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/rnqc-invalidate.XXXXXX")
trap 'rm -rf "$work"' EXIT

gh api --paginate --slurp "repos/$REPO/pulls?state=open&base=$DEFAULT_BRANCH&per_page=100" > "$work/pages.json"
jq -e 'type == "array" and all(.[]; type == "array")' "$work/pages.json" >/dev/null
jq -c --arg base "$DEFAULT_BRANCH" '
  flatten
  | map(select(.base.ref == $base) | {number, head: .head.sha})
  | if length > 1000 then error("more than 1000 supported open pull requests") else . end
  | if all(.[]; (.number | type == "number") and (.head | test("^[0-9a-f]{40}$"))) then . else error("invalid pull request response") end
' "$work/pages.json" > "$work/pulls.json"

jq -r 'map(.head) | unique[]' "$work/pulls.json" > "$work/heads.txt"
while IFS= read -r head; do
  [[ -n $head ]] || continue
  gh api --method POST "repos/$REPO/statuses/$head" \
    -f state=pending \
    -f context=agentscm/local-validation \
    -f description='reconciling trusted local E2E attestations' \
    -f target_url="$RUN_URL" >/dev/null
done < "$work/heads.txt"

echo "invalidated $(wc -l < "$work/heads.txt" | tr -d ' ') supported head(s)"
