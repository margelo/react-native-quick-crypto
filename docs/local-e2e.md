# Local iOS and Android E2E attestations

RNQC runs its expensive iOS and Android device suites on a maintainer workstation and uses a signed AgentSCM attestation as the merge signal. For this local-E2E gate, GitHub runs only the small verifier in `.github/workflows/local-validation.yml`; that verifier never checks out, builds or executes pull request code. Unrelated static and validation workflows may still execute pull request code.

The required status context is `agentscm/local-validation`. It is not a claim that GitHub ran the mobile suites. It means an enrolled key signed an AgentSCM `worker_asserted` record for the exact repository, head commit, tree, base ref, merge-base, recipe, policy and registry that the default-branch verifier observed.

## Gate definition

The trusted files are read from `main`:

- `.github/local-validation/recipe.json` requires both `bun run e2e:ios` and `bun run e2e:android`, in that order. Either command failing stops the run and produces a signed failure.
- `.github/local-validation/policy.json` binds the recipe digest, repository identity, 30-day maximum age and policy epoch. PostgreSQL and S3 are not RNQC dependencies and are not required.
- `.github/local-validation/registry.json` enrolls the public `boorad` Ed25519 key for `command/v1`. Its validity is 2026-10-23 10:38:40 UTC through 2027-10-23 11:38:40 UTC. The public record was reused with explicit authorization; no private key was copied. Revocation requires a reviewed registry change and epoch update.
- `scripts/local-validation/agentscm-rnqc.patch` is a narrow compatibility patch over AgentSCM commit `24b70c0796e8288d1560adda36a1590e613d0ffc`. It replaces AgentSCM's Rust-repository dependency labels with `bun.lock` and `package.json`, records Bun/Node/Git tool versions, and honors the policy's optional service flags when producing the signed outcome.

AgentSCM `v0.1.0-alpha.6` contains local validation, but it has the same Rust-only assumptions as the pinned revision, so the release binary is not valid for producing RNQC attestations. `scripts/local-validation/build-agentscm.sh` checks the exact source revision, exports it to a temporary directory, applies the reviewed compatibility patch there, builds with the source-pinned Rust toolchain and leaves the AgentSCM checkout untouched. The verifier builds the same source and patch and caches Rust build inputs.

## Trust and coverage limits

The attestation is worker-asserted. A valid signature proves that the enrolled private-key holder signed the bound record; it does not independently prove that the commands ran, that the host was uncompromised or that screenshots depict the run.

Recipe commands run as the signing user, not in a sandbox. AgentSCM clears the environment and passes only `PATH`, `HOME`, `USER`, `TMPDIR`, `LANG`, `CARGO_HOME`, `RUSTUP_HOME`, `CARGO_TARGET_DIR` and `AGENTSCM_TEST_*`. The E2E runner must therefore work without `ANDROID_HOME`, `ANDROID_SDK_ROOT`, `JAVA_HOME` or `DEVELOPER_DIR`. Its macOS fallbacks are `$HOME/Library/Android/sdk` and `/Applications/Android Studio.app/Contents/jbr/Contents/Home`; custom installations are unsupported by this recipe until the runner can discover them without those environment variables.

AgentSCM always writes these upstream fixed omissions into the signed envelope: `ignored tests`, `windows`, `container smoke`, `hub end-to-end` and `live execution`. The latter three are AgentSCM-oriented labels and do not describe additional RNQC suites; they remain present because the upstream evidence profile hardcodes them. With this policy the envelope also honestly lists `postgres tests` and `s3 tests` as omitted even though RNQC does not require those services. RNQC's positive coverage is only the exact two recipe commands on the signing host and the simulator/emulator versions recorded by the E2E results.

The base branch tip is not bound. The merge-base is bound, and retargeting changes the expected base context, but a later fast-forward of `main` does not invalidate an attestation when the merge-base is unchanged. Requiring branches to be up to date in the ruleset mitigates this limit. Pull requests that share one head commit across different bases also share commit statuses; only pull requests targeting `main` are supported by this rollout.

## Artifact contract

Each runner invocation writes one run directory:

```text
example/build/e2e/<platform>/<run-id>/result.json
example/build/e2e/<platform>/<run-id>/<platform>-test-result.png
```

Before exiting, the runner hashes each artifact that exists and prints this exact single-line format to standard output:

```text
ARTIFACT_SHA256 sha256=<64 lowercase hex> path=<absolute artifact path>
```

The result line ends in `/result.json`; the screenshot line ends in `/ios-test-result.png` or `/android-test-result.png`. A missing artifact is reported as `ARTIFACT_SHA256 missing path=<absolute artifact path>` and cannot satisfy screenshot posting. AgentSCM retains each command's stdout and commits its SHA-256 in the signed record. The separate screenshot helper recomputes each artifact hash, confirms the matching hash/path-suffix line is present in the matching retained stdout, and confirms the retained stdout hash matches the signed record. This binds the hashes, not the mutable image-hosting URL, to the attestation.

The runner must write and close `result.json` and the PNG before hashing them. A successful result has `schemaVersion: 1`, `status: "passed"`, the matching `platform`, and `revision.commit` equal to the attested head. `example/build/` is ignored, so these outputs do not dirty the Git tree.

## Build the compatible AgentSCM binary

Use the clean AgentSCM source checkout at the pinned revision and place the output outside RNQC:

```bash
git -C /Users/brad/dev/cb/agentscm status --short
git -C /Users/brad/dev/cb/agentscm rev-parse HEAD
./scripts/local-validation/build-agentscm.sh /Users/brad/dev/cb/agentscm /tmp/rnqc-agentscm-24b70c0
```

The first command must print nothing and the second must print `24b70c0796e8288d1560adda36a1590e613d0ffc`.

Qualify the patched producer and verifier without running RNQC E2E or contacting GitHub:

```bash
./scripts/local-validation/test-agentscm.sh /Users/brad/dev/cb/agentscm
./scripts/local-validation/qualify-agentscm.sh /tmp/rnqc-agentscm-24b70c0
./scripts/local-validation/test-scripts.sh
```

The patched AgentSCM tests cover optional and required services, JavaScript dependency labels and digests, missing dependency files, and stopping at the first failed command. The qualifier creates a disposable Git repository and synthetic Ed25519 key, signs and verifies success and failure records, checks the `bun.lock` and `package.json` dependency claims with PostgreSQL and S3 disabled, and exercises changed-head, tampered-record, trusted-recipe-mismatch, wrong-repository, wrong-base, changed-registry, revoked-key and newest-signed-failure verdicts. The shell regressions use mocked GitHub and ImgBB commands to cover pagination, comment deletion and marker removal, interleaved evidence deletion before publication, pre-setup invalidation and retry, unsupported bases, shared heads and refusal to upload invalid screenshot evidence after all downstream prerequisites are valid. Every fixture trap removes its repository, keys, retained attestations and other temporary files. These tests never read the enrolled `boorad` private key, post a pull request comment or change a GitHub ruleset.

## Produce and post an attestation

Run only reviewed code on the signing host. The private key and state directory must be outside the repository and owner-private. Do not put GitHub or ImgBB credentials in recipe-command environment variables.

```bash
git fetch origin main
git status --short
git diff --exit-code origin/main -- .github/local-validation/recipe.json .github/local-validation/policy.json .github/local-validation/registry.json
mkdir -m 700 /absolute/private/path/rnqc-attestations

/tmp/rnqc-agentscm-24b70c0 local-validation run \
  --repo . \
  --recipe .github/local-validation/recipe.json \
  --policy .github/local-validation/policy.json \
  --registry .github/local-validation/registry.json \
  --key-file /absolute/private/path/boorad.ed25519 \
  --issuer-id boorad \
  --state-dir /absolute/private/path/rnqc-attestations \
  --base-ref main \
  --base-rev origin/main
```

`git status --short` must print nothing before `run`, and the trust-input comparison must exit successfully. Checkout-relative recipe, policy, and registry paths are safe here only because they exactly match fetched `origin/main`. If the PR changes those inputs, stop; their trusted default-branch update must be reviewed and landed first. Save the `envelope_sha256` from its JSON output as `ATTESTATION`. AgentSCM retains the signed envelope, record and two commands' stdout/stderr under the state directory. A successful run contains both results; a failed iOS command intentionally omits Android and verifies as failure.

Create an owner-private, single-line GitHub token file with permission to read the pull request and write its comments, then explicitly post the attestation:

```bash
/tmp/rnqc-agentscm-24b70c0 local-validation post \
  --state-dir /absolute/private/path/rnqc-attestations \
  --attestation "$ATTESTATION" \
  --github-repo margelo/react-native-quick-crypto \
  --pr 123 \
  --token-file /absolute/private/path/github-token
```

`post` refuses when the current pull request head differs from the signed commit. The default-branch workflow independently validates the signature and publishes `agentscm/local-validation` on that exact head. Do not post statuses by hand.

## Post screenshot evidence

Screenshot posting is separate because AgentSCM `local-validation post` carries only the signed envelope and record. The helper uploads to ImgBB using the same 30-day expiry as the removed hosted-E2E action and creates or updates one PR comment bound to the PR head and attestation digest. It does nothing without the explicit `--post` flag.

Before uploading, repeat the fetch and trust-input comparison above; stop on any mismatch. The helper reads checkout-relative trust inputs, so this check is required even when reusing an existing attestation. Use the two run directories printed by the E2E runner:

```bash
./scripts/local-validation/post-screenshots.sh \
  --post \
  --pr 123 \
  --attestation "$ATTESTATION" \
  --state-dir /absolute/private/path/rnqc-attestations \
  --agentscm-bin /tmp/rnqc-agentscm-24b70c0 \
  --ios-artifacts example/build/e2e/ios/<run-id> \
  --android-artifacts example/build/e2e/android/<run-id> \
  --github-token-file /absolute/private/path/github-token \
  --imgbb-api-key-file /absolute/private/path/imgbb-api-key
```

The helper also accepts `GH_TOKEN` and `IMGBB_API_KEY` instead of files. It never prints either secret or the ImgBB deletion URLs. It refuses stale heads, non-`main` targets, invalid or unsuccessful attestations, missing trusted attestation comments, incomplete artifacts, result/head mismatches and hashes absent from signed stdout.

## Verifier behavior

The verifier runs from trusted `main` code on:

- creation, editing or deletion of a trusted attestation comment;
- pull request open, synchronize, reopen or edit events for pull requests targeting `main`;
- changes on `main` to policy, recipe, registry, the verifier workflow or the compatibility build inputs;
- a daily schedule, which expires old successes and repairs missed events.

All eligible status-writing jobs share one repository-wide concurrency group; skipped jobs from ordinary comments never enter it and therefore cannot displace a queued deletion or attestation event. GitHub may replace an older pending job with a newer eligible event, so every surviving job reconciles every supported open pull request targeting `main`, regardless of which PR triggered it. Before checkout, toolchain setup or AgentSCM build, the workflow discovers every supported head through the paginated GitHub API and replaces its old verdict with `pending`. If checkout, setup, build or reconciliation fails, an `always()` finalizer repeats that invalidation. Listing or pagination errors fail closed and are retried by the finalizer; a persistent GitHub API outage is reported as a failed workflow rather than a successful reconciliation.

Comment edits that remove the marker and comment deletions produce `pending`. A new head gets its own `pending` or verified verdict. Retargeting to `main` re-evaluates the same head against its new base and merge-base. Pull requests not targeting `main` are never published by this workflow, including when their comment caused the repository-wide reconciliation. If multiple supported open PRs share one head commit, the shared commit status cannot safely represent independent comment threads, so the verifier publishes `pending` with `head shared by multiple open main PRs; unsupported`. Before posting any final verdict, each job rechecks the complete paginated trusted-comment fingerprints plus PR state, head and base for every supported pull request, then repeats the relevant checks immediately before each status write. It also rechecks the trusted verifier inputs. A race or partial read aborts publication and the finalizer restores every supported head to `pending`.

The workflow checks out `main` into one directory and pinned AgentSCM source into another. It fetches `refs/pull/<number>/head` only into the trusted RNQC Git object database. No command uses the pull request worktree or files. There is intentionally no `workflow_dispatch`, because GitHub permits dispatching a workflow from a non-default ref and the verifier has `statuses: write`.

## Required-check rollout

No live ruleset change is part of this migration. Ruleset `657234` (`main`) was inspected on 2026-10-26: it is active for `~DEFAULT_BRANCH` and contains only deletion and non-fast-forward protections.

After this change is on `main`, complete all of these steps before making the status required:

1. Confirm the default-branch verifier builds the pinned, patched AgentSCM source and posts `pending` to an open PR with no attestation.
2. From a clean checkout of that PR head, run both local device suites, post the signed attestation and screenshots, and confirm `agentscm/local-validation` becomes `success` on that exact SHA.
3. Edit the attestation comment to remove its marker and confirm the same SHA becomes `pending`; restore or repost the valid body and confirm `success` returns.
4. Delete the attestation comment and confirm the same SHA remains `pending`. Push a new head and confirm it is `pending` until separately attested.
5. Retarget a test PR to `main` and confirm the verifier re-evaluates the base context. Confirm a comment on a non-`main` PR never publishes that PR's head, even when it shares a commit with another PR.
6. Open two `main` PRs on the same head and confirm the context remains `pending` with the documented unsupported-ambiguity reason.
7. Force a verifier setup failure after the first invalidation step and confirm every supported head is `pending`; repeat with a transient paginated-list failure and confirm the finalizer retry restores `pending`.
8. Review the `boorad` public-key validity window and establish the renewal/revocation owner before expiry.
9. Edit ruleset `657234` and add one required status check with the exact context `agentscm/local-validation`, sourced from GitHub Actions when GitHub offers an app selector. Enable the option requiring branches to be up to date before merging. Do not add the deleted hosted E2E job names as required checks.
10. Confirm an unattested PR is blocked and a freshly attested, unambiguous PR is mergeable. Preserve the no-bypass posture unless maintainers deliberately approve and document an emergency path.

The migration PR itself cannot be gated by a verifier that is not yet on `main`; enabling the required context before merge would deadlock rollout. If qualification exposes a verifier bug, keep the ruleset unchanged, fix and requalify from the new default-branch revision, then repeat the rollout.
