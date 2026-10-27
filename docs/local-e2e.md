# Local iOS and Android E2E attestations

RNQC runs its expensive iOS and Android device suites on a maintainer workstation and uses a signed AgentSCM attestation as the merge signal. For this local-E2E gate, GitHub runs only the small verifier in `.github/workflows/local-validation.yml`; that verifier never checks out, builds or executes pull request code. Unrelated static and validation workflows may still execute pull request code.

The required status context is `agentscm/local-validation`. It is not a claim that GitHub ran the mobile suites. It means an enrolled key signed an AgentSCM `worker_asserted` record for the exact repository, head commit, tree, base ref, merge-base, recipe, policy and registry that the default-branch verifier observed.

## Gate definition

The trusted files are read from `main`:

- `.github/local-validation/recipe.json` requires both `bun run e2e:ios` and `bun run e2e:android`, in that order. Either command failing stops the run and produces a signed failure.
- `.github/local-validation/policy.json` binds the recipe digest, repository identity, 30-day maximum age and policy epoch. PostgreSQL and S3 are not RNQC dependencies and are not required.
- `.github/local-validation/registry.json` enrolls the public `boorad` Ed25519 key for `command/v1`. Its validity is 2026-10-23 10:38:40 UTC through 2027-10-23 11:38:40 UTC. The public record was reused with explicit authorization; no private key was copied. Revocation requires a reviewed registry change and epoch update.
- `.github/local-validation/recipe.json` also declares `bun.lock` and `package.json` as `dependency_files` and Bun and Node version `toolchain_probes`, so the signed evidence binds RNQC's JavaScript inputs instead of AgentSCM's Rust defaults.
- `policy.json` declares `exempt_paths`. A pull request whose every changed path matches one of them gets `success` with `not required: only exempt paths changed`, without an attestation. This means it was exempted, not tested on devices. Changes to `.github/local-validation/**` or `.github/workflows/local-validation.yml` are never exempt.

RNQC uses unpatched AgentSCM built from source at the commit pinned as `AGENTSCM_REVISION` in `.github/workflows/local-validation.yml`. No published AgentSCM release contains `local-validation reconcile`, recipe dependency files or `exempt_paths` yet. The producer and the verifier must be built from the same commit.

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

## Build AgentSCM

Use a clean AgentSCM checkout at the pinned commit and place the binary outside RNQC:

```bash
REV=$(sed -n 's/^  AGENTSCM_REVISION: //p' .github/workflows/local-validation.yml)
git -C /Users/brad/dev/cb/agentscm fetch origin
git -C /Users/brad/dev/cb/agentscm worktree add --detach /tmp/agentscm-rnqc "$REV"
(cd /tmp/agentscm-rnqc && cargo build --locked --release --bin agentscm)
install -m 0755 /tmp/agentscm-rnqc/target/release/agentscm /tmp/rnqc-agentscm
```

AgentSCM's own test suite covers producing, verifying and reconciling attestations, path-scoped commands and exempt paths. `./scripts/local-validation/test-scripts.sh` covers RNQC's screenshot helper with mocked GitHub and ImgBB commands, including refusal to upload invalid screenshot evidence. These tests never read the enrolled `boorad` private key, post a pull request comment or change a GitHub ruleset.

## Produce and post an attestation

Run only reviewed code on the signing host. The private key and state directory must be outside the repository and owner-private. Do not put GitHub or ImgBB credentials in recipe-command environment variables.

```bash
git fetch origin main
git status --short
git diff --exit-code origin/main -- .github/local-validation/recipe.json .github/local-validation/policy.json .github/local-validation/registry.json
mkdir -m 700 /absolute/private/path/rnqc-attestations

/tmp/rnqc-agentscm local-validation run \
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
/tmp/rnqc-agentscm local-validation post \
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
  --agentscm-bin /tmp/rnqc-agentscm \
  --ios-artifacts example/build/e2e/ios/<run-id> \
  --android-artifacts example/build/e2e/android/<run-id> \
  --github-token-file /absolute/private/path/github-token \
  --imgbb-api-key-file /absolute/private/path/imgbb-api-key
```

The helper also accepts `GH_TOKEN` and `IMGBB_API_KEY` instead of files. It never prints either secret or the ImgBB deletion URLs. It refuses stale heads, non-`main` targets, invalid or unsuccessful attestations, missing trusted attestation comments, incomplete artifacts, result/head mismatches and hashes absent from signed stdout.

## Verifier behavior

The verifier workflow builds the pinned AgentSCM commit and runs `agentscm local-validation reconcile` from a checkout of `main`. It runs on:

- creation, editing or deletion of a trusted attestation comment;
- pull request open, synchronize or reopen events, and base changes, for pull requests targeting `main`;
- changes on `main` to the policy, recipe, registry or the verifier workflow;
- a daily schedule, which expires old successes and repairs missed events.

Every run sweeps all open pull requests on `main`, so one repository-wide job-level concurrency group is enough; ignored comments never enter it. `reconcile` sets `pending` on every opted-in head first, verifies trusted attestation comments, and re-reads pull request state and comments immediately before each status write. Comment deletions and edits that remove the marker produce `pending`. A head shared by several open pull requests gets `pending` as unsupported. Pull request heads are fetched from `origin` as Git data only and are never checked out, built or run. There is intentionally no `workflow_dispatch`, because the verifier has `statuses: write`. AgentSCM's `docs/advanced/local-validation.md` documents `reconcile`'s full behavior and limits.

## Required-check rollout

No live ruleset change is part of this migration. Ruleset `657234` (`main`) was inspected on 2026-10-26: it is active for `~DEFAULT_BRANCH` and contains only deletion and non-fast-forward protections.

After this change is on `main`, complete all of these steps before making the status required:

1. Confirm the default-branch verifier builds the pinned AgentSCM source and posts `pending` to an open PR with no attestation.
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
