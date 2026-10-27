#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly SCRIPT_DIR

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
readonly curl_calls="$test_root/curl-calls"
readonly pull_pages="$test_root/pull-pages.json"
mkdir -p "$mock_bin" "$comments_dir"
: > "$calls"
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
  file="$MOCK_COMMENTS_DIR/${BASH_REMATCH[1]}.json"
  if [[ -f $file ]]; then
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
exit 0
MOCK_GIT

cat > "$mock_bin/agentscm" <<'MOCK_AGENTSCM'
#!/usr/bin/env bash
printf '{"state":"success","reason":"validated"}\n'
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
export MOCK_CURL_CALLS=$curl_calls
export MOCK_PULL_PAGES=$pull_pages
export MOCK_COMMENTS_DIR=$comments_dir

pull() {
  local number=$1 head=$2
  jq -cn --argjson number "$number" --arg head "$head" \
    '{number:$number,state:"open",head:{sha:$head},base:{ref:"main"}}'
}

set_pull_pages() {
  printf '%s\n' "$1" > "$pull_pages"
  : > "$calls"
}

set_comments() {
  printf '%s\n' "$2" > "$comments_dir/$1.json"
}

readonly head_a=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

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

echo 'screenshot helper regression passed'
