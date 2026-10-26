#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 AGENTSCM_BINARY" >&2
  exit 2
fi

readonly AGENTSCM_BIN=$1
[[ -x $AGENTSCM_BIN ]] || { echo "AgentSCM binary is not executable: $AGENTSCM_BIN" >&2; exit 1; }

fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/rnqc-local-validation.XXXXXX")
cleanup() {
  case $fixture_root in
    "${TMPDIR:-/tmp}"/rnqc-local-validation.*) rm -rf -- "$fixture_root" ;;
    *) echo "refusing to remove unexpected fixture path: $fixture_root" >&2 ;;
  esac
}
trap cleanup EXIT

readonly repo="$fixture_root/repo"
readonly config="$fixture_root/config"
readonly state="$fixture_root/state"
readonly data="$fixture_root/data"
readonly key="$fixture_root/synthetic.ed25519"
readonly repository=github.com/example/rnqc-local-validation-fixture
readonly issuer=synthetic-qualifier

mkdir -p "$repo" "$config"
git -C "$repo" init -q -b main
git -C "$repo" config user.name 'RNQC local validation qualifier'
git -C "$repo" config user.email 'rnqc-local-validation@example.invalid'
printf '{"lockfileVersion":1}\n' > "$repo/bun.lock"
printf '{"name":"rnqc-local-validation-fixture","private":true}\n' > "$repo/package.json"
git -C "$repo" add bun.lock package.json
git -C "$repo" commit -q -m 'fixture: base'
git -C "$repo" switch -q -c feature
git -C "$repo" commit -q --allow-empty -m 'fixture: success head'
success_head=$(git -C "$repo" rev-parse HEAD)
readonly success_head

cat > "$config/success-recipe.json" <<'JSON'
{"recipe_id":"rnqc-synthetic-success-v1","commands":[{"id":"synthetic-success","argv":["/bin/sh","-c","printf 'synthetic success\\n'"],"timeout_secs":30}]}
JSON
cat > "$config/failure-recipe.json" <<'JSON'
{"recipe_id":"rnqc-synthetic-failure-v1","commands":[{"id":"synthetic-failure","argv":["/bin/sh","-c","printf 'synthetic failure\\n' >&2; exit 7"],"timeout_secs":30}]}
JSON
cat > "$config/mismatch-recipe.json" <<'JSON'
{"recipe_id":"rnqc-synthetic-mismatch-v1","commands":[{"id":"synthetic-mismatch","argv":["/bin/true"],"timeout_secs":30}]}
JSON
jq -n --arg marker "$fixture_root/newest-failure" '{
  recipe_id: "rnqc-synthetic-selection-v1",
  commands: [{
    id: "synthetic-selection",
    argv: ["/bin/sh", "-c", "test ! -e \"$1\"", "synthetic-selection", $marker],
    timeout_secs: 30
  }]
}' > "$config/selection-recipe.json"

sha256_stdin() {
  shasum -a 256 | awk '{print $1}'
}

success_recipe_sha=$(jq -cj . "$config/success-recipe.json" | sha256_stdin)
failure_recipe_sha=$(jq -cj . "$config/failure-recipe.json" | sha256_stdin)
selection_recipe_sha=$(jq -cj . "$config/selection-recipe.json" | sha256_stdin)
cat > "$config/success-policy.json" <<JSON
{"repository":"$repository","recipe_sha256":"$success_recipe_sha","required_services":{"postgres":false,"s3":false},"max_age_seconds":3600,"epoch":1}
JSON
cat > "$config/failure-policy.json" <<JSON
{"repository":"$repository","recipe_sha256":"$failure_recipe_sha","required_services":{"postgres":false,"s3":false},"max_age_seconds":3600,"epoch":1}
JSON
cat > "$config/selection-policy.json" <<JSON
{"repository":"$repository","recipe_sha256":"$selection_recipe_sha","required_services":{"postgres":false,"s3":false},"max_age_seconds":3600,"epoch":1}
JSON

key_output=$(
  "$AGENTSCM_BIN" --data-dir "$data" --no-telemetry agent-task key-generate "$key"
)
public_key=$(jq -er .public_key_hex <<<"$key_output")
key_id=$(jq -er .verification_key_id <<<"$key_output")
[[ $public_key != f1af50baaf94c581e7204881da7fb16dff93d4a167b67c3693caf587238aab72 ]] || {
  echo "synthetic key unexpectedly equals the enrolled boorad key" >&2
  exit 1
}
cat > "$config/registry.json" <<JSON
{"version":1,"repository":"$repository","epoch":1,"issuers":[{"issuer_id":"$issuer","trust_domain":"synthetic-test","common_control":{"state":"unknown"},"allowed_check_kinds":["command/v1"],"keys":[{"key_id":"$key_id","public_key_hex":"$public_key","not_before_ms":1,"not_after_ms":4102444800000}]}]}
JSON

run_validation() {
  local recipe=$1 policy=$2
  "$AGENTSCM_BIN" --data-dir "$data" --no-telemetry local-validation run \
    --repo "$repo" \
    --recipe "$recipe" \
    --policy "$policy" \
    --registry "$config/registry.json" \
    --key-file "$key" \
    --issuer-id "$issuer" \
    --state-dir "$state" \
    --base-ref main \
    --base-rev main
}

show_validation() {
  "$AGENTSCM_BIN" --data-dir "$data" --no-telemetry local-validation show \
    --state-dir "$state" \
    --attestation "$1"
}

verify_comment_as() {
  local comment=$1 recipe=$2 policy=$3 head=$4 observed_repository=$5 observed_base=$6 registry=$7
  "$AGENTSCM_BIN" --data-dir "$data" --no-telemetry local-validation verify \
    --comment-body "$comment" \
    --policy "$policy" \
    --recipe "$recipe" \
    --registry "$registry" \
    --repo "$repo" \
    --head "$head" \
    --base-ref "$observed_base" \
    --base-rev main \
    --repository "$observed_repository"
}

verify_comment() {
  verify_comment_as "$1" "$2" "$3" "$4" "$repository" main "$config/registry.json"
}

verify_two_comments() {
  local first=$1 second=$2 recipe=$3 policy=$4 head=$5
  "$AGENTSCM_BIN" --data-dir "$data" --no-telemetry local-validation verify \
    --comment-body "$first" \
    --comment-body "$second" \
    --policy "$policy" \
    --recipe "$recipe" \
    --registry "$config/registry.json" \
    --repo "$repo" \
    --head "$head" \
    --base-ref main \
    --base-rev main \
    --repository "$repository"
}

expect_verdict() {
  local expected_exit=$1 expected_state=$2 expected_reason=$3 output_file=$4
  shift 4
  local output exit_code
  set +e
  output=$("$@")
  exit_code=$?
  set -e
  printf '%s\n' "$output" > "$output_file"
  [[ $exit_code -eq $expected_exit ]] || { echo "expected exit $expected_exit, got $exit_code: $output" >&2; exit 1; }
  [[ $(jq -er .state <<<"$output") == "$expected_state" ]] || { echo "expected state $expected_state: $output" >&2; exit 1; }
  [[ $(jq -er .reason <<<"$output") == "$expected_reason" ]] || { echo "expected reason $expected_reason: $output" >&2; exit 1; }
}

success_run=$(run_validation "$config/success-recipe.json" "$config/success-policy.json")
success_attestation=$(jq -er .envelope_sha256 <<<"$success_run")
[[ $(jq -er .outcome <<<"$success_run") == pass ]] || { echo "success run did not produce pass" >&2; exit 1; }
readonly success_envelope="$state/$success_attestation.envelope.json"
readonly success_record="$state/$success_attestation.record.json"
readonly success_comment="$fixture_root/success-comment.md"
show_validation "$success_attestation" > "$success_comment"

expect_verdict 0 success validated "$fixture_root/success-verdict.json" \
  verify_comment "$success_comment" "$config/success-recipe.json" "$config/success-policy.json" "$success_head"
[[ $(jq -er .envelope_sha256 "$fixture_root/success-verdict.json") == "$success_attestation" ]] || {
  echo "success verdict did not identify the signed envelope" >&2
  exit 1
}

[[ $(jq -er .payload.outcome "$success_envelope") == pass ]] || { echo "signed success envelope is not pass" >&2; exit 1; }
jq -e '.services == {"postgres":false,"s3":false} and .tree_unchanged_after == true' "$success_record" >/dev/null || {
  echo "success record did not preserve optional services and clean tree" >&2
  exit 1
}
bun_sha=$(git -C "$repo" show "$success_head:bun.lock" | sha256_stdin)
package_sha=$(git -C "$repo" show "$success_head:package.json" | sha256_stdin)
jq -e --arg bun "$bun_sha" --arg package "$package_sha" '
  .payload.dependencies == [
    {"identity":"bun.lock","state":{"state":"resolved","revision":$bun}},
    {"identity":"package.json","state":{"state":"resolved","revision":$package}}
  ]
' "$success_envelope" >/dev/null || { echo "signed dependency claims do not bind bun.lock and package.json" >&2; exit 1; }

git -C "$repo" commit -q --allow-empty -m 'fixture: changed head'
changed_head=$(git -C "$repo" rev-parse HEAD)
readonly changed_head
expect_verdict 3 pending 'no attestation for this head' "$fixture_root/changed-head-verdict.json" \
  verify_comment "$success_comment" "$config/success-recipe.json" "$config/success-policy.json" "$changed_head"
jq -e '.detail | contains("stale attestation")' "$fixture_root/changed-head-verdict.json" >/dev/null || {
  echo "changed-head verdict did not report a stale attestation" >&2
  exit 1
}

expect_verdict 3 pending 'no attestation for this head' "$fixture_root/wrong-repository-verdict.json" \
  verify_comment_as "$success_comment" "$config/success-recipe.json" "$config/success-policy.json" "$success_head" \
  github.com/example/wrong-repository main "$config/registry.json"
jq -e '.detail | contains("wrong repository")' "$fixture_root/wrong-repository-verdict.json" >/dev/null || {
  echo "wrong-repository attestation was not ignored" >&2
  exit 1
}

expect_verdict 3 pending 'no attestation for this head' "$fixture_root/wrong-base-verdict.json" \
  verify_comment_as "$success_comment" "$config/success-recipe.json" "$config/success-policy.json" "$success_head" \
  "$repository" release "$config/registry.json"
jq -e '.detail | contains("stale attestation")' "$fixture_root/wrong-base-verdict.json" >/dev/null || {
  echo "wrong-base attestation was not ignored" >&2
  exit 1
}

jq '.epoch = 2 | .issuers = []' "$config/registry.json" > "$config/wrong-registry.json"
expect_verdict 3 pending 'no attestation for this head' "$fixture_root/wrong-registry-verdict.json" \
  verify_comment_as "$success_comment" "$config/success-recipe.json" "$config/success-policy.json" "$success_head" \
  "$repository" main "$config/wrong-registry.json"

jq '.issuers[0].keys[0].revoked_at_ms = 1' "$config/registry.json" > "$config/revoked-registry.json"
expect_verdict 3 pending 'no attestation for this head' "$fixture_root/revoked-verdict.json" \
  verify_comment_as "$success_comment" "$config/success-recipe.json" "$config/success-policy.json" "$success_head" \
  "$repository" main "$config/revoked-registry.json"
jq -e '.detail | contains("issuer registry stale") or contains("issuer not trusted")' "$fixture_root/revoked-verdict.json" >/dev/null || {
  echo "revoked issuer attestation was not ignored" >&2
  exit 1
}

jq '.platform = "tampered-synthetic-platform"' "$success_record" > "$fixture_root/tampered-record.json"
{
  head -n 1 "$success_comment"
  printf '\n%s\n' '```agentscm-envelope-v1'
  base64 < "$success_envelope" | tr -d '\n' | fold -w 76
  printf '\n%s\n\n%s\n' '```' '```agentscm-record-v1'
  base64 < "$fixture_root/tampered-record.json" | tr -d '\n' | fold -w 76
  printf '\n%s\n' '```'
} > "$fixture_root/tampered-comment.md"
expect_verdict 3 pending 'no attestation for this head' "$fixture_root/tampered-verdict.json" \
  verify_comment "$fixture_root/tampered-comment.md" "$config/success-recipe.json" "$config/success-policy.json" "$success_head"
jq -e '.detail | contains("record not committed")' "$fixture_root/tampered-verdict.json" >/dev/null || {
  echo "tampered-record verdict did not reject the record commitment" >&2
  exit 1
}

expect_verdict 2 error 'recipe does not match policy' "$fixture_root/recipe-mismatch-verdict.json" \
  verify_comment "$success_comment" "$config/mismatch-recipe.json" "$config/success-policy.json" "$success_head"
jq -e '.detail == "the trusted recipe differs from the policy digest"' "$fixture_root/recipe-mismatch-verdict.json" >/dev/null || {
  echo "trusted recipe mismatch did not fail closed" >&2
  exit 1
}

set +e
failure_run=$(run_validation "$config/failure-recipe.json" "$config/failure-policy.json")
failure_run_exit=$?
set -e
[[ $failure_run_exit -eq 1 ]] || { echo "expected signed failure run exit 1, got $failure_run_exit: $failure_run" >&2; exit 1; }
failure_attestation=$(jq -er .envelope_sha256 <<<"$failure_run")
[[ $(jq -er .outcome <<<"$failure_run") == fail ]] || { echo "failure run did not produce fail" >&2; exit 1; }
readonly failure_envelope="$state/$failure_attestation.envelope.json"
readonly failure_comment="$fixture_root/failure-comment.md"
show_validation "$failure_attestation" > "$failure_comment"
expect_verdict 1 failure 'command failed' "$fixture_root/failure-verdict.json" \
  verify_comment "$failure_comment" "$config/failure-recipe.json" "$config/failure-policy.json" "$changed_head"
[[ $(jq -er .payload.outcome "$failure_envelope") == fail ]] || { echo "signed failure envelope is not fail" >&2; exit 1; }
[[ $(jq -er .envelope_sha256 "$fixture_root/failure-verdict.json") == "$failure_attestation" ]] || {
  echo "failure verdict did not identify the signed envelope" >&2
  exit 1
}

selection_pass_run=$(run_validation "$config/selection-recipe.json" "$config/selection-policy.json")
selection_pass=$(jq -er .envelope_sha256 <<<"$selection_pass_run")
readonly selection_pass_comment="$fixture_root/selection-pass.md"
show_validation "$selection_pass" > "$selection_pass_comment"
sleep 0.02
: > "$fixture_root/newest-failure"
set +e
selection_failure_run=$(run_validation "$config/selection-recipe.json" "$config/selection-policy.json")
selection_failure_exit=$?
set -e
[[ $selection_failure_exit -eq 1 ]] || { echo "newest selection failure did not fail" >&2; exit 1; }
selection_failure=$(jq -er .envelope_sha256 <<<"$selection_failure_run")
readonly selection_failure_comment="$fixture_root/selection-failure.md"
show_validation "$selection_failure" > "$selection_failure_comment"
expect_verdict 1 failure 'command failed' "$fixture_root/newest-failure-verdict.json" \
  verify_two_comments "$selection_failure_comment" "$selection_pass_comment" \
  "$config/selection-recipe.json" "$config/selection-policy.json" "$changed_head"
[[ $(jq -er .envelope_sha256 "$fixture_root/newest-failure-verdict.json") == "$selection_failure" ]] || {
  echo "newest signed failure did not win selection" >&2
  exit 1
}

jq -n \
  --arg binary "$AGENTSCM_BIN" \
  --arg success_head "$success_head" \
  --arg changed_head "$changed_head" \
  --arg success_attestation "$success_attestation" \
  --arg failure_attestation "$failure_attestation" \
  --arg selection_failure_attestation "$selection_failure" \
  --slurpfile success "$fixture_root/success-verdict.json" \
  --slurpfile failure "$fixture_root/failure-verdict.json" \
  --slurpfile changed "$fixture_root/changed-head-verdict.json" \
  --slurpfile tampered "$fixture_root/tampered-verdict.json" \
  --slurpfile mismatch "$fixture_root/recipe-mismatch-verdict.json" \
  --slurpfile wrong_repository "$fixture_root/wrong-repository-verdict.json" \
  --slurpfile wrong_base "$fixture_root/wrong-base-verdict.json" \
  --slurpfile wrong_registry "$fixture_root/wrong-registry-verdict.json" \
  --slurpfile revoked "$fixture_root/revoked-verdict.json" \
  --slurpfile newest_failure "$fixture_root/newest-failure-verdict.json" '
  {
    binary: $binary,
    synthetic_key: true,
    services: {postgres: false, s3: false},
    dependencies: ["bun.lock", "package.json"],
    success: ($success[0] + {run_exit: 0, verify_exit: 0, head: $success_head, attestation: $success_attestation}),
    failure: ($failure[0] + {run_exit: 1, verify_exit: 1, head: $changed_head, attestation: $failure_attestation}),
    changed_head: ($changed[0] + {verify_exit: 3}),
    tampered_record: ($tampered[0] + {verify_exit: 3}),
    trusted_recipe_mismatch: ($mismatch[0] + {verify_exit: 2}),
    wrong_repository: ($wrong_repository[0] + {verify_exit: 3}),
    wrong_base: ($wrong_base[0] + {verify_exit: 3}),
    wrong_registry: ($wrong_registry[0] + {verify_exit: 3}),
    revoked_key: ($revoked[0] + {verify_exit: 3}),
    newest_signed_failure: ($newest_failure[0] + {verify_exit: 1, attestation: $selection_failure_attestation}),
    fixture_cleaned_on_exit: true
  }'
