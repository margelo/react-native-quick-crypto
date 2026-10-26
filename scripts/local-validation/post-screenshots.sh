#!/usr/bin/env bash

set -euo pipefail
set +x

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly SCRIPT_DIR
REPO_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
readonly REPO_DIR
readonly DEFAULT_REPOSITORY=margelo/react-native-quick-crypto

repository=$DEFAULT_REPOSITORY
agentscm_bin=agentscm
state_dir=
attestation=
pull_request=
ios_artifacts=
android_artifacts=
github_token_file=
imgbb_api_key_file=
post=false

usage() {
  cat >&2 <<'EOF'
usage: post-screenshots.sh --post --pr NUMBER --attestation SHA256 --state-dir DIR \
  --ios-artifacts DIR --android-artifacts DIR [--agentscm-bin FILE] \
  [--repository OWNER/NAME] [--github-token-file FILE] [--imgbb-api-key-file FILE]
EOF
  exit 2
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --post) post=true; shift ;;
    --pr) pull_request=${2-}; shift 2 ;;
    --attestation) attestation=${2-}; shift 2 ;;
    --state-dir) state_dir=${2-}; shift 2 ;;
    --ios-artifacts) ios_artifacts=${2-}; shift 2 ;;
    --android-artifacts) android_artifacts=${2-}; shift 2 ;;
    --agentscm-bin) agentscm_bin=${2-}; shift 2 ;;
    --repository) repository=${2-}; shift 2 ;;
    --github-token-file) github_token_file=${2-}; shift 2 ;;
    --imgbb-api-key-file) imgbb_api_key_file=${2-}; shift 2 ;;
    *) usage ;;
  esac
done

[[ $post == true ]] || { echo "refusing to post without --post" >&2; exit 2; }
[[ $pull_request =~ ^[1-9][0-9]*$ ]] || usage
[[ $attestation =~ ^[0-9a-f]{64}$ ]] || usage
[[ -n $state_dir && -n $ios_artifacts && -n $android_artifacts ]] || usage
[[ $repository =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || usage

for command in curl gh jq shasum; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done
[[ -x $agentscm_bin ]] || command -v "$agentscm_bin" >/dev/null || { echo "AgentSCM binary not found: $agentscm_bin" >&2; exit 1; }

read_secret_file() {
  local file=$1 value
  [[ $file == /* && -f $file ]] || { echo "secret file must be an absolute regular file" >&2; exit 1; }
  value=$(<"$file")
  [[ -n $value && $value != *$'\n'* && $value != *$'\r'* ]] || { echo "secret file must contain one non-empty line" >&2; exit 1; }
  printf '%s' "$value"
}

if [[ -n $github_token_file ]]; then
  GH_TOKEN=$(read_secret_file "$github_token_file")
  export GH_TOKEN
fi
if [[ -n $imgbb_api_key_file ]]; then
  IMGBB_API_KEY=$(read_secret_file "$imgbb_api_key_file")
  export IMGBB_API_KEY
fi
: "${GH_TOKEN:?set GH_TOKEN or pass --github-token-file}"
: "${IMGBB_API_KEY:?set IMGBB_API_KEY or pass --imgbb-api-key-file}"

readonly envelope_file="$state_dir/$attestation.envelope.json"
readonly record_file="$state_dir/$attestation.record.json"
[[ -f $envelope_file && -f $record_file ]] || { echo "retained attestation files not found" >&2; exit 1; }
[[ $(shasum -a 256 "$envelope_file" | awk '{print $1}') == "$attestation" ]] || { echo "attestation digest does not match the retained envelope" >&2; exit 1; }

pull_json=$(mktemp "${TMPDIR:-/tmp}/rnqc-pull.XXXXXX")
comments_json=$(mktemp "${TMPDIR:-/tmp}/rnqc-comments.XXXXXX")
body_file=$(mktemp "${TMPDIR:-/tmp}/rnqc-comment.XXXXXX")
payload_file=$(mktemp "${TMPDIR:-/tmp}/rnqc-payload.XXXXXX")
trap 'rm -f "$pull_json" "$comments_json" "$body_file" "$payload_file"' EXIT

gh api "repos/$repository/pulls/$pull_request" > "$pull_json"
head_sha=$(jq -er .head.sha "$pull_json")
base_ref=$(jq -er .base.ref "$pull_json")
[[ $base_ref == main ]] || { echo "PR #$pull_request targets $base_ref, not main" >&2; exit 1; }
[[ $(jq -er .subject.commit "$record_file") == "$head_sha" ]] || { echo "PR head differs from the retained attestation" >&2; exit 1; }

git -C "$REPO_DIR" fetch --no-tags origin "+refs/heads/$base_ref:refs/remotes/origin/$base_ref"
verify_output=$(
  "$agentscm_bin" local-validation verify \
    --envelope "$envelope_file" \
    --record "$record_file" \
    --policy "$REPO_DIR/.github/local-validation/policy.json" \
    --recipe "$REPO_DIR/.github/local-validation/recipe.json" \
    --registry "$REPO_DIR/.github/local-validation/registry.json" \
    --repo "$REPO_DIR" \
    --head "$head_sha" \
    --base-ref "$base_ref" \
    --base-rev "origin/$base_ref" \
    --repository "github.com/$repository"
)
[[ $(jq -er .state <<<"$verify_output") == success ]] || { echo "attestation does not verify as success" >&2; exit 1; }

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

verify_artifacts() {
  local platform=$1 directory=$2 index=$3 result screenshot result_sha screenshot_sha stdout_file expected_stdout_sha
  result="$directory/result.json"
  screenshot="$directory/$platform-test-result.png"
  stdout_file="$state_dir/$attestation.cmd$((index + 1)).stdout"
  [[ -f $result && -f $screenshot && -f $stdout_file ]] || { echo "$platform evidence files are incomplete" >&2; exit 1; }
  jq -e --arg platform "$platform" --arg head "$head_sha" \
    '.schemaVersion == 1 and .status == "passed" and .platform == $platform and .revision.commit == $head' \
    "$result" >/dev/null || { echo "$platform result.json is not a passing result for $head_sha" >&2; exit 1; }
  result_sha=$(sha256_file "$result")
  screenshot_sha=$(sha256_file "$screenshot")
  expected_stdout_sha=$(jq -er --argjson index "$index" '.results[$index].stdout_sha256' "$record_file")
  [[ $(sha256_file "$stdout_file") == "$expected_stdout_sha" ]] || { echo "$platform retained stdout does not match the signed record" >&2; exit 1; }
  grep -Eq "^ARTIFACT_SHA256 sha256=$result_sha path=.+/result\\.json$" "$stdout_file" || { echo "$platform result hash is absent from signed stdout" >&2; exit 1; }
  grep -Eq "^ARTIFACT_SHA256 sha256=$screenshot_sha path=.+/$platform-test-result\\.png$" "$stdout_file" || { echo "$platform screenshot hash is absent from signed stdout" >&2; exit 1; }
  printf '%s %s' "$result_sha" "$screenshot_sha"
}

ios_hashes=$(verify_artifacts ios "$ios_artifacts" 0) || exit $?
read -r ios_result_sha ios_screenshot_sha <<<"$ios_hashes"
android_hashes=$(verify_artifacts android "$android_artifacts" 1) || exit $?
read -r android_result_sha android_screenshot_sha <<<"$android_hashes"

gh api --paginate --slurp "repos/$repository/issues/$pull_request/comments?per_page=100" > "$comments_json"
readonly attestation_marker="<!-- agentscm-local-validation:v1 $attestation -->"
jq -e --arg marker "$attestation_marker" '
  flatten | any(.[]; (.body | startswith($marker)) and (.author_association == "OWNER" or .author_association == "MEMBER" or .author_association == "COLLABORATOR"))
' "$comments_json" >/dev/null || { echo "trusted attestation comment is not present on PR #$pull_request" >&2; exit 1; }

upload_image() {
  local image=$1 response url
  response=$(mktemp "${TMPDIR:-/tmp}/rnqc-imgbb.XXXXXX")
  if ! curl --fail --silent --show-error --request POST https://api.imgbb.com/1/upload \
    --form-string "key=$IMGBB_API_KEY" --form "expiration=2592000" --form "image=@$image" > "$response"; then
    rm -f "$response"
    return 1
  fi
  if ! url=$(jq -er '.data.url' "$response"); then
    rm -f "$response"
    return 1
  fi
  rm -f "$response"
  printf '%s' "$url"
}

ios_url=$(upload_image "$ios_artifacts/ios-test-result.png")
android_url=$(upload_image "$android_artifacts/android-test-result.png")
readonly evidence_marker="<!-- rnqc-local-e2e-evidence:v1 head=$head_sha attestation=$attestation -->"
cat > "$body_file" <<EOF
$evidence_marker

## Local device E2E evidence

- Head: \`$head_sha\`
- AgentSCM attestation: \`$attestation\`
- iOS result SHA-256: \`$ios_result_sha\`
- iOS screenshot SHA-256: \`$ios_screenshot_sha\`
- Android result SHA-256: \`$android_result_sha\`
- Android screenshot SHA-256: \`$android_screenshot_sha\`

| Platform | Final screenshot |
| --- | --- |
| iOS | <img src="$ios_url" alt="iOS local E2E result" width="400" /> |
| Android | <img src="$android_url" alt="Android local E2E result" width="400" /> |

The hashes above are present in command stdout committed by the signed attestation. Images expire after 30 days; the hashes remain the durable binding.
EOF

login=$(gh api user --jq .login)
comment_id=$(jq -r --arg marker "$evidence_marker" --arg login "$login" '
  flatten | map(select(.user.login == $login and (.body | startswith($marker)))) | first | .id // empty
' "$comments_json")
jq -n --rawfile body "$body_file" '{body: $body}' > "$payload_file"
if [[ -n $comment_id ]]; then
  gh api --method PATCH "repos/$repository/issues/comments/$comment_id" --input "$payload_file" >/dev/null
else
  gh api --method POST "repos/$repository/issues/$pull_request/comments" --input "$payload_file" >/dev/null
fi

echo "Posted local E2E screenshot evidence for $head_sha to PR #$pull_request"
