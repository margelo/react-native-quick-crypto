#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly SCRIPT_DIR
REPO_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
readonly REPO_DIR

test_root=$(mktemp -d "${TMPDIR:-/tmp}/rnqc-local-validation-scripts.XXXXXX")
cleanup() {
  case $test_root in
    "${TMPDIR:-/tmp}"/rnqc-local-validation-scripts.*) rm -rf -- "$test_root" ;;
    *) echo "refusing to remove unexpected test path: $test_root" >&2 ;;
  esac
}
trap cleanup EXIT

readonly mock_bin="$test_root/bin"
readonly comments_dir="$test_root/comments"
readonly calls="$test_root/gh-calls"
readonly statuses="$test_root/statuses"
readonly curl_calls="$test_root/curl-calls"
readonly pull_pages="$test_root/pull-pages.json"
mkdir -p "$mock_bin" "$comments_dir" "$test_root/runner"
: > "$calls"
: > "$statuses"
: > "$curl_calls"

cat > "$mock_bin/gh" <<'MOCK_GH'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >> "$MOCK_GH_CALLS"
printf '\n' >> "$MOCK_GH_CALLS"
endpoint=
for argument in "$@"; do
  [[ $argument == repos/* ]] && endpoint=$argument
done
if [[ $endpoint == *'/pulls?state=open&base='* ]]; then
  [[ ${MOCK_GH_FAIL_LIST:-false} == false ]] || exit 1
  cat "$MOCK_PULL_PAGES"
  exit 0
fi
if [[ $endpoint =~ /statuses/([0-9a-f]{40})$ ]]; then
  state=
  description=
  previous=
  for argument in "$@"; do
    [[ $previous == -f && $argument == state=* ]] && state=${argument#state=}
    [[ $previous == -f && $argument == description=* ]] && description=${argument#description=}
    previous=$argument
  done
  printf '%s\t%s\t%s\n' "${BASH_REMATCH[1]}" "$state" "$description" >> "$MOCK_STATUS_LOG"
  exit 0
fi
if [[ $endpoint =~ /pulls/([0-9]+)$ ]]; then
  number=${BASH_REMATCH[1]}
  pull=$(jq -cer --argjson number "$number" 'flatten[] | select(.number == $number)' "$MOCK_PULL_PAGES")
  if [[ " $* " == *' --jq '* ]]; then
    jq -r '[.state, .head.sha, .base.ref] | join(":")' <<<"$pull"
  else
    printf '%s\n' "$pull"
  fi
  exit 0
fi
if [[ $endpoint =~ /issues/([0-9]+)/comments ]]; then
  number=${BASH_REMATCH[1]}
  sequence="$MOCK_COMMENTS_DIR/$number.sequence.json"
  file="$MOCK_COMMENTS_DIR/$number.json"
  if [[ -f $sequence ]]; then
    counter="$MOCK_COMMENTS_DIR/$number.count"
    count=0
    [[ ! -f $counter ]] || count=$(<"$counter")
    printf '%s\n' "$((count + 1))" > "$counter"
    jq -c --argjson index "$count" '.[if $index < length then $index else length - 1 end]' "$sequence"
  elif [[ -f $file ]]; then
    cat "$file"
  else
    printf '[[]]\n'
  fi
  exit 0
fi
if [[ $endpoint == user ]]; then
  printf '{"login":"synthetic-user"}\n'
  exit 0
fi
echo "unexpected gh invocation: $*" >&2
exit 1
MOCK_GH

cat > "$mock_bin/git" <<'MOCK_GIT'
#!/usr/bin/env bash
set -euo pipefail
case " $* " in
  *' rev-parse HEAD '*) printf '%040d\n' 0 ;;
  *) exit 0 ;;
esac
MOCK_GIT

cat > "$mock_bin/agentscm" <<'MOCK_AGENTSCM'
#!/usr/bin/env bash
set -euo pipefail
case ${MOCK_AGENTSCM_STATE:-success} in
  success) printf '{"state":"success","reason":"validated"}\n'; exit 0 ;;
  failure) printf '{"state":"failure","reason":"command failed"}\n'; exit 1 ;;
  pending) printf '{"state":"pending","reason":"no attestation for this head"}\n'; exit 3 ;;
  *) printf '{"state":"error","reason":"input error"}\n'; exit 2 ;;
esac
MOCK_AGENTSCM

cat > "$mock_bin/curl" <<'MOCK_CURL'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >> "$MOCK_CURL_CALLS"
printf '\n' >> "$MOCK_CURL_CALLS"
printf '{"data":{"url":"https://example.invalid/image.png"}}\n'
MOCK_CURL
chmod 0755 "$mock_bin/gh" "$mock_bin/git" "$mock_bin/agentscm" "$mock_bin/curl"

export PATH="$mock_bin:$PATH"
export MOCK_GH_CALLS=$calls
export MOCK_STATUS_LOG=$statuses
export MOCK_CURL_CALLS=$curl_calls
export MOCK_PULL_PAGES=$pull_pages
export MOCK_COMMENTS_DIR=$comments_dir
export GH_TOKEN=synthetic-token
export REPO=margelo/react-native-quick-crypto
export DEFAULT_BRANCH=main
export RUN_URL=https://example.invalid/run
export RUNNER_TEMP="$test_root/runner"
export AGENTSCM_BIN="$mock_bin/agentscm"

assert_status() {
  local head=$1 state=$2
  grep -Eq "^${head}[[:space:]]+${state}([[:space:]]|$)" "$statuses" || {
    echo "missing $state status for $head" >&2
    cat "$statuses" >&2
    exit 1
  }
}

assert_no_status() {
  local head=$1
  if grep -q "^$head" "$statuses"; then
    echo "unexpected status for $head" >&2
    cat "$statuses" >&2
    exit 1
  fi
}

pull() {
  local number=$1 head=$2 base=${3:-main}
  jq -cn --argjson number "$number" --arg head "$head" --arg base "$base" \
    '{number:$number,state:"open",head:{sha:$head},base:{ref:$base}}'
}

set_pull_pages() {
  printf '%s\n' "$1" > "$pull_pages"
  rm -f "$comments_dir"/*.count
  : > "$statuses"
  : > "$calls"
}

set_comments() {
  local pr=$1 json=$2
  rm -f "$comments_dir/$pr.sequence.json" "$comments_dir/$pr.count"
  printf '%s\n' "$json" > "$comments_dir/$pr.json"
}

set_comment_sequence() {
  local pr=$1 json=$2
  rm -f "$comments_dir/$pr.json" "$comments_dir/$pr.count"
  printf '%s\n' "$json" > "$comments_dir/$pr.sequence.json"
}

readonly head_a=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
readonly head_b=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
readonly head_c=cccccccccccccccccccccccccccccccccccccccc
readonly head_d=dddddddddddddddddddddddddddddddddddddddd
pull_a=$(pull 1 "$head_a")
pull_b=$(pull 2 "$head_b" other)
pull_c=$(pull 3 "$head_c")

# The trusted workflow embeds the exact pre-checkout invalidator that is regression-tested here.
ruby -ryaml -e '
  run = YAML.load_file(ARGV.fetch(0), aliases: true).fetch("jobs").fetch("verify").fetch("steps").first.fetch("run")
  start = run.index("#!/usr/bin/env bash") or abort("missing invalidator start")
  finish = run.index("\nINVALIDATE_SCRIPT", start) or abort("missing invalidator end")
  print run[start...finish], "\n"
' "$REPO_DIR/.github/workflows/local-validation.yml" > "$test_root/embedded-invalidator.sh"
cmp -s "$SCRIPT_DIR/invalidate-heads.sh" "$test_root/embedded-invalidator.sh" || {
  echo "workflow pre-checkout invalidator differs from the tested script" >&2
  exit 1
}

# Pagination covers every supported main PR and filters an unsupported base.
set_pull_pages "[[$pull_a,$pull_b],[$pull_c]]"
"$SCRIPT_DIR/invalidate-heads.sh" >/dev/null
assert_status "$head_a" pending
assert_status "$head_c" pending
assert_no_status "$head_b"

# A later setup failure cannot restore the statuses invalidated before setup.
set +e
false
setup_exit=$?
set -e
[[ $setup_exit -ne 0 ]] || { echo "synthetic setup failure did not fail" >&2; exit 1; }
"$SCRIPT_DIR/invalidate-heads.sh" >/dev/null
assert_status "$head_a" pending
assert_status "$head_c" pending

# An early listing failure is non-success; a finalizer retry can still invalidate every head.
: > "$statuses"
export MOCK_GH_FAIL_LIST=true
if "$SCRIPT_DIR/invalidate-heads.sh" >/dev/null 2>&1; then
  echo "pull-list API failure unexpectedly succeeded" >&2
  exit 1
fi
[[ ! -s $statuses ]] || { echo "API failure posted a partial status" >&2; exit 1; }
unset MOCK_GH_FAIL_LIST
"$SCRIPT_DIR/invalidate-heads.sh" >/dev/null
assert_status "$head_a" pending
assert_status "$head_c" pending

printf '{"not":"paginated arrays"}\n' > "$pull_pages"
: > "$statuses"
if "$SCRIPT_DIR/invalidate-heads.sh" >/dev/null 2>&1; then
  echo "malformed pagination unexpectedly succeeded" >&2
  exit 1
fi
[[ ! -s $statuses ]] || { echo "malformed pagination posted a partial status" >&2; exit 1; }

valid_body='<!-- agentscm-local-validation:v1 synthetic --> valid'
valid_comment=$(jq -cn --arg body "$valid_body" '{id:10,updated_at:"2026-01-01T00:00:00Z",author_association:"OWNER",body:$body}')
removed_comment=$(jq -cn '{id:11,updated_at:"2026-01-01T00:00:01Z",author_association:"OWNER",body:"marker removed"}')

# A trusted marker found on a later comment page can produce success.
set_pull_pages "[[$pull_a]]"
set_comments 1 "[[{\"id\":9,\"updated_at\":\"2026-01-01T00:00:00Z\",\"author_association\":\"NONE\",\"body\":\"noise\"}],[$valid_comment]]"
(cd "$REPO_DIR" && "$SCRIPT_DIR/reconcile-heads.sh" >/dev/null)
assert_status "$head_a" success

# Evidence for A deleted while B is being verified aborts before any queued success is published.
pull_interleaved_b=$(pull 2 "$head_c")
set_pull_pages "[[$pull_a,$pull_interleaved_b]]"
comment_pages="[[$valid_comment]]"
set_comment_sequence 1 "[$comment_pages,$comment_pages,[[]]]"
set_comments 2 '[[]]'
"$SCRIPT_DIR/invalidate-heads.sh" >/dev/null
set +e
(cd "$REPO_DIR" && "$SCRIPT_DIR/reconcile-heads.sh" >"$test_root/interleaving.out" 2>&1)
interleaving_exit=$?
set -e
[[ $interleaving_exit -ne 0 ]] || { echo "interleaved comment deletion unexpectedly reconciled" >&2; exit 1; }
assert_status "$head_a" pending
assert_status "$head_c" pending
if grep -Eq "^(${head_a}|${head_c})[[:space:]]+success([[:space:]]|$)" "$statuses"; then
  echo "interleaved comment deletion published a stale success" >&2
  exit 1
fi
grep -q 'trusted attestation comments changed on PR 1' "$test_root/interleaving.out"

# Deletion and marker removal both reconcile the supported head back to pending.
set_pull_pages "[[$pull_a]]"
set_comments 1 '[[]]'
(cd "$REPO_DIR" && "$SCRIPT_DIR/reconcile-heads.sh" >/dev/null)
assert_status "$head_a" pending
set_pull_pages "[[$pull_a]]"
set_comments 1 "[[$removed_comment]]"
(cd "$REPO_DIR" && "$SCRIPT_DIR/reconcile-heads.sh" >/dev/null)
assert_status "$head_a" pending

# A shared supported head is explicitly rejected even if one PR has valid evidence.
pull_shared_1=$(pull 1 "$head_d")
pull_shared_2=$(pull 2 "$head_d")
set_pull_pages "[[$pull_shared_1,$pull_shared_2]]"
set_comments 1 "[[$valid_comment]]"
set_comments 2 '[[]]'
(cd "$REPO_DIR" && "$SCRIPT_DIR/reconcile-heads.sh" >/dev/null)
assert_status "$head_d" pending
grep -q 'head shared by multiple open main PRs; unsupported' "$statuses"

# A non-main PR returned by a faulty/mocked filter never receives or influences a status.
set_pull_pages "[[$pull_a,$pull_b]]"
set_comments 1 "[[$valid_comment]]"
(cd "$REPO_DIR" && "$SCRIPT_DIR/reconcile-heads.sh" >/dev/null)
assert_status "$head_a" success
assert_no_status "$head_b"

# Invalid signed-output evidence must fail before ImgBB upload or any comment mutation.
readonly screenshot_root="$test_root/screenshots"
readonly state_dir="$screenshot_root/state"
readonly ios_dir="$screenshot_root/ios"
readonly android_dir="$screenshot_root/android"
mkdir -p "$state_dir" "$ios_dir" "$android_dir"
printf '{}' > "$screenshot_root/envelope"
attestation=$(shasum -a 256 "$screenshot_root/envelope" | awk '{print $1}')
cp "$screenshot_root/envelope" "$state_dir/$attestation.envelope.json"
printf 'signed stdout without artifact commitments\n' > "$state_dir/$attestation.cmd1.stdout"
printf 'unused android stdout\n' > "$state_dir/$attestation.cmd2.stdout"
ios_stdout_sha=$(shasum -a 256 "$state_dir/$attestation.cmd1.stdout" | awk '{print $1}')
android_stdout_sha=$(shasum -a 256 "$state_dir/$attestation.cmd2.stdout" | awk '{print $1}')
jq -cn --arg head "$head_a" --arg ios "$ios_stdout_sha" --arg android "$android_stdout_sha" \
  '{subject:{commit:$head},results:[{stdout_sha256:$ios},{stdout_sha256:$android}]}' > "$state_dir/$attestation.record.json"
jq -n --arg head "$head_a" '{schemaVersion:1,status:"passed",platform:"ios",revision:{commit:$head}}' > "$ios_dir/result.json"
jq -n --arg head "$head_a" '{schemaVersion:1,status:"passed",platform:"android",revision:{commit:$head}}' > "$android_dir/result.json"
printf 'ios screenshot\n' > "$ios_dir/ios-test-result.png"
printf 'android screenshot\n' > "$android_dir/android-test-result.png"
pull_123=$(pull 123 "$head_a")
set_pull_pages "[[$pull_123]]"
screenshot_comment=$(jq -cn --arg body "<!-- agentscm-local-validation:v1 $attestation --> synthetic" \
  '{id:1230,updated_at:"2026-01-01T00:00:00Z",author_association:"OWNER",body:$body}')
set_comments 123 "[[$screenshot_comment]]"
: > "$curl_calls"
set +e
GH_TOKEN=synthetic-token IMGBB_API_KEY=synthetic-key "$SCRIPT_DIR/post-screenshots.sh" \
  --post --pr 123 --attestation "$attestation" --state-dir "$state_dir" \
  --agentscm-bin "$mock_bin/agentscm" --ios-artifacts "$ios_dir" --android-artifacts "$android_dir" \
  > "$test_root/screenshot.out" 2>&1
screenshot_exit=$?
set -e
[[ $screenshot_exit -ne 0 ]] || { echo "invalid screenshot evidence unexpectedly succeeded" >&2; exit 1; }
grep -q 'ios result hash is absent from signed stdout' "$test_root/screenshot.out" || {
  echo "invalid screenshot evidence did not fail at the artifact commitment check" >&2
  cat "$test_root/screenshot.out" >&2
  exit 1
}
[[ ! -s $curl_calls ]] || { echo "invalid screenshot evidence reached upload" >&2; exit 1; }
if grep -Eq -- '--method (POST|PATCH)' "$calls"; then
  echo "invalid screenshot evidence reached comment mutation" >&2
  exit 1
fi

echo 'local-validation shell regressions passed'
