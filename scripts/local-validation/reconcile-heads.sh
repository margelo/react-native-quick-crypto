#!/usr/bin/env bash

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${REPO:?REPO is required}"
: "${DEFAULT_BRANCH:?DEFAULT_BRANCH is required}"
: "${RUN_URL:?RUN_URL is required}"
: "${AGENTSCM_BIN:?AGENTSCM_BIN is required}"

readonly marker='<!-- agentscm-local-validation:v1 '
readonly config=.github/local-validation
readonly trusted='["OWNER","MEMBER","COLLABORATOR"]'
checkout_sha=$(git rev-parse HEAD)
readonly checkout_sha
repository=$(jq -er .repository "$config/policy.json")
readonly repository
[[ $repository == "github.com/$REPO" ]] || { echo "policy repository $repository does not match github.com/$REPO" >&2; exit 1; }

work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/rnqc-reconcile.XXXXXX")
trap 'rm -rf "$work"' EXIT

readonly -a verifier_inputs=(
  '.github/local-validation/**'
  .github/workflows/local-validation.yml
  scripts/local-validation/agentscm-rnqc.patch
  scripts/local-validation/build-agentscm.sh
  scripts/local-validation/invalidate-heads.sh
  scripts/local-validation/reconcile-heads.sh
)

check_verifier_inputs() {
  git fetch --no-tags origin "$DEFAULT_BRANCH"
  if ! git diff --quiet "$checkout_sha" FETCH_HEAD -- "${verifier_inputs[@]}"; then
    echo "default-branch verifier inputs changed; refusing to publish a stale verdict" >&2
    return 1
  fi
}

post_status() {
  local sha=$1 state=$2 description=$3
  gh api --method POST "repos/$REPO/statuses/$sha" \
    -f state="$state" \
    -f context=agentscm/local-validation \
    -f description="${description:0:140}" \
    -f target_url="$RUN_URL" >/dev/null
}

read_pages() {
  local endpoint=$1 destination=$2 limit=$3
  gh api --paginate --slurp "$endpoint" > "$destination"
  jq -e --argjson limit "$limit" '
    type == "array" and all(.[]; type == "array") and (flatten | length <= $limit)
  ' "$destination" >/dev/null || { echo "invalid, truncated or oversized paginated response: $endpoint" >&2; return 1; }
}

read_supported_pulls() {
  local pages=$1 destination=$2
  read_pages "repos/$REPO/pulls?state=open&base=$DEFAULT_BRANCH&per_page=100" "$pages" 1000
  jq -c --arg base "$DEFAULT_BRANCH" '
    flatten
    | map(select(.base.ref == $base) | {number, head: .head.sha, base: .base.ref})
    | if all(.[]; (.number | type == "number") and (.head | test("^[0-9a-f]{40}$"))) then . else error("invalid pull request response") end
    | sort_by(.number)
  ' "$pages" > "$destination"
}

read_comment_fingerprint() {
  local pr=$1 destination=$2 pages
  pages="$destination.pages.json"
  read_pages "repos/$REPO/issues/$pr/comments?per_page=100" "$pages" 1000
  jq -r --arg marker "$marker" --argjson trusted "$trusted" "flatten | $fingerprint_filter" "$pages" | sort > "$destination"
}

validate_snapshot() {
  local pr=$1 head=$2 expected_fingerprint=$3 destination=$4 pull
  read_comment_fingerprint "$pr" "$destination"
  cmp -s "$expected_fingerprint" "$destination" || {
    echo "trusted attestation comments changed on PR $pr" >&2
    return 1
  }
  pull=$(gh api "repos/$REPO/pulls/$pr" --jq '[.state, .head.sha, .base.ref] | join(":")')
  [[ $pull == "open:$head:$DEFAULT_BRANCH" ]] || {
    echo "state, head or base changed on PR $pr" >&2
    return 1
  }
}

read_supported_pulls "$work/pull-pages.json" "$work/pulls.json"

# shellcheck disable=SC2016 # jq variables, not shell expansions
readonly selector='.[] | select((.body | startswith($marker)) and (.author_association as $a | $trusted | index($a)))'
# shellcheck disable=SC2016 # jq interpolation, not shell interpolation
readonly fingerprint_filter="$selector | \"\(.id):\(.updated_at)\""

verify_pr() {
  local pr=$1 expected_head=$2 directory="$work/pr-$1" head base count output code expected pull_after
  local state description
  local -a args=()
  mkdir -p "$directory"
  gh api "repos/$REPO/pulls/$pr" > "$directory/pull-before.json"
  head=$(jq -er .head.sha "$directory/pull-before.json")
  base=$(jq -er .base.ref "$directory/pull-before.json")
  [[ $head == "$expected_head" && $base == "$DEFAULT_BRANCH" ]] || return 2
  git check-ref-format "refs/heads/$base" >/dev/null
  git fetch --no-tags origin "+refs/heads/$base:refs/remotes/origin/$base"
  git fetch --no-tags origin "refs/pull/$pr/head"
  git cat-file -e "$head^{commit}"

  read_pages "repos/$REPO/issues/$pr/comments?per_page=100" "$directory/comment-pages.json" 1000
  jq -c 'flatten' "$directory/comment-pages.json" > "$directory/comments.json"
  jq -r --arg marker "$marker" --argjson trusted "$trusted" "$fingerprint_filter" "$directory/comments.json" | sort > "$directory/fingerprint-before.txt"
  jq -c --arg marker "$marker" --argjson trusted "$trusted" "$selector | .body" "$directory/comments.json" > "$directory/bodies.jsonl"
  count=0
  while IFS= read -r body; do
    count=$((count + 1))
    printf '%s' "$body" | jq -r . > "$directory/comment-$count.txt"
    args+=(--comment-body "$directory/comment-$count.txt")
  done < "$directory/bodies.jsonl"

  if [[ $count -eq 0 ]]; then
    state=pending
    description="PR $pr has no trusted local E2E attestation"
  else
    code=0
    output=$(
      "$AGENTSCM_BIN" local-validation verify "${args[@]}" \
        --policy "$config/policy.json" \
        --recipe "$config/recipe.json" \
        --registry "$config/registry.json" \
        --repo . \
        --head "$head" \
        --base-ref "$base" \
        --base-rev "origin/$base" \
        --repository "$repository"
    ) || code=$?
    state=error
    case $code in
      0) expected=success ;;
      1) expected=failure ;;
      2) expected=error ;;
      3) expected=pending ;;
      *) expected= ;;
    esac
    if [[ -n $expected && $(jq -r .state 2>/dev/null <<<"$output") == "$expected" ]]; then
      state=$expected
    fi
    description=$(jq -r '.reason // empty' 2>/dev/null <<<"$output" || true)
    description=${description:-verifier error (exit $code)}
  fi

  read_pages "repos/$REPO/issues/$pr/comments?per_page=100" "$directory/comment-pages-after.json" 1000
  jq -c 'flatten' "$directory/comment-pages-after.json" > "$directory/comments-after.json"
  jq -r --arg marker "$marker" --argjson trusted "$trusted" "$fingerprint_filter" "$directory/comments-after.json" | sort > "$directory/fingerprint-after.txt"
  cmp -s "$directory/fingerprint-before.txt" "$directory/fingerprint-after.txt" || return 2
  pull_after=$(gh api "repos/$REPO/pulls/$pr" --jq '[.state, .head.sha, .base.ref] | join(":")')
  [[ $pull_after == "open:$head:$base" ]] || return 2
  jq -cn --argjson pr "$pr" --arg head "$head" --arg state "$state" --arg description "$description" \
    '{pr:$pr,head:$head,state:$state,description:$description}' > "$directory/result.json"
}

: > "$work/results.jsonl"
while IFS=$'\t' read -r pr head; do
  [[ -n $pr ]] || continue
  set +e
  (set -euo pipefail; verify_pr "$pr" "$head")
  verify_code=$?
  set -e
  if [[ $verify_code -eq 0 ]]; then
    result=$(<"$work/pr-$pr/result.json")
    state=$(jq -er .state <<<"$result")
    description=$(jq -er .description <<<"$result")
  else
    state=error
    description="PR $pr changed or verification failed; re-run"
  fi
  case $state in
    success) severity=1 ;;
    pending) severity=2 ;;
    failure) severity=3 ;;
    error) severity=4 ;;
    *) echo "unexpected state: $state" >&2; exit 1 ;;
  esac
  jq -cn --argjson pr "$pr" --arg head "$head" --arg state "$state" --arg description "$description" --argjson severity "$severity" \
    '{pr:$pr,head:$head,state:$state,description:$description,severity:$severity}' >> "$work/results.jsonl"
done < <(jq -r '.[] | [.number, .head] | @tsv' "$work/pulls.json")

read_supported_pulls "$work/pull-pages-after.json" "$work/pulls-after.json"
cmp -s "$work/pulls.json" "$work/pulls-after.json" || {
  echo "supported pull request set changed during reconciliation" >&2
  exit 1
}

# Bind every queued verdict to one complete publication-boundary snapshot before any status is
# written. If evidence for an earlier PR changed while a later PR was being verified, the initial
# workflow invalidation remains authoritative and the failure finalizer repeats it.
while IFS=$'\t' read -r pr head; do
  [[ -n $pr ]] || continue
  fingerprint="$work/pr-$pr/fingerprint-after.txt"
  [[ -f $fingerprint ]] || {
    echo "PR $pr lacks a verified comment fingerprint" >&2
    exit 1
  }
  validate_snapshot "$pr" "$head" "$fingerprint" "$work/pr-$pr/fingerprint-publication.txt" || exit 1
done < <(jq -r '.[] | [.number, .head] | @tsv' "$work/pulls.json")

jq -sc 'group_by(.head)[]' "$work/results.jsonl" > "$work/groups.jsonl"
while IFS= read -r group; do
  [[ -n $group ]] || continue
  head=$(jq -r '.[0].head' <<<"$group")
  count=$(jq length <<<"$group")
  if [[ $count -gt 1 ]]; then
    state=pending
    description="head shared by multiple open main PRs; unsupported"
  else
    state=$(jq -r 'max_by(.severity).state' <<<"$group")
    description=$(jq -r 'max_by(.severity).description' <<<"$group")
  fi
  check_verifier_inputs
  while IFS=$'\t' read -r pr expected_head; do
    [[ -n $pr ]] || continue
    validate_snapshot "$pr" "$expected_head" "$work/pr-$pr/fingerprint-publication.txt" "$work/pr-$pr/fingerprint-immediate.txt" || exit 1
  done < <(jq -r '.[] | [.pr, .head] | @tsv' <<<"$group")
  post_status "$head" "$state" "$description"
done < "$work/groups.jsonl"

echo "reconciled $(jq length "$work/pulls.json") supported open PR(s)"
