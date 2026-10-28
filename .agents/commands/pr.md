# /pr - Create or Update a Pull Request

Create or update the PR for the current branch. Invoking `/pr` authorizes the qualified push, attestation comment, and screenshot publication required for this workflow.

## Instructions

### 1. Establish accurate scope

```bash
git fetch origin
BRANCH=$(git branch --show-current)
git status --short
git log origin/main..HEAD --oneline
git diff --stat origin/main...HEAD
git diff --name-only origin/main...HEAD
```

Abort on `main`. The working tree must be clean before push. Use `origin/main`, not a potentially stale local `main`, and use the three-dot diff for PR scope.

### 2. Confirm qualification

Review current evidence for the actual HEAD and every changed toolchain. A qualified branch has:

- Required commits created through mandatory hooks.
- Relevant scoped checks passing at the current SHA.
- Native behavior built and exercised on the relevant platform when the diff requires it.
- No unverified runtime behavior that could change the diff, unless the user explicitly directed shipment and the PR discloses the gap and risk.
- An independent local review completed without waiting for a bot.
- When the native merge gate applies, final attestation is still pending until it binds the final committed HEAD; earlier raw E2E evidence may support review but does not replace that receipt.

Do not rerun still-current broad evidence merely to open the PR.

### 3. Complete the exact plan lifecycle

If the branch identifier is `<type>/<N>-<slug>`, look only for `plans/todo/<N>-<slug>.md`. Do not fuzzy-match or create a retroactive plan.

If that exact plan exists and the implementation is complete:

```bash
mkdir -p plans/done
git mv plans/todo/<N>-<slug>.md plans/done/<N>-<slug>.md
rm -f .agents/progress/claude-progress.md
```

Carry genuinely outstanding verification items with an owner, then commit the move through `/commit` before pushing. If multiple candidates exist or the work is incomplete, move none and report the mismatch.

### 4. Reuse an existing PR

Check for a PR whose head is the current branch:

```bash
gh pr list --head "$BRANCH" --state all --json number,url,state,title,headRefOid
```

Reuse an open PR instead of creating a duplicate. If the only matching PR is closed or merged, stop and report before creating another.

### 5. Build the PR description from the actual diff

Write the body to a temporary Markdown file and pass it with `--body-file`. Include:

- **Summary:** outcome and rationale.
- **Changes:** concrete branch changes.
- **Testing:** exact commands, results, commit SHA, and native platform. Distinguish reused evidence from checks run during PR preparation.
- **Delivery:** what merging actually delivers. Agent/docs changes take effect in the repository on merge; CI changes alter validation on merge; package TypeScript/C++/Nitro changes reach consumers only after an npm release; native changes additionally require the consuming app to rebuild and ship. Example-app-only changes do not publish the library.
- **Not verified:** only explicit residue and risk, if shipment was authorized despite it.
- **Issue:** `Fixes #N` or `Closes #N` when the PR resolves the issue.

Derive issue references from the exact branch identifier, issue context, and commits. Do not attach unrelated recent issues.

### 6. Push and create or update

```bash
git push -u origin "$BRANCH"
```

Never use `--no-verify`. Verify the remote branch SHA matches local HEAD before continuing.

For an existing open PR, update it:

```bash
gh pr edit <number> --title "<title>" --body-file <body-file>
```

Otherwise create it:

```bash
gh pr create --title "<title>" --body-file <body-file> --base main --assignee @me
```

Use a conventional-commit-style title unless the user supplied one.

### 7. Complete attested native qualification when required

Follow `docs/local-e2e.md` rather than duplicating its commands. Use the trusted recipe, policy, and registry from `main` with the documented pinned AgentSCM producer on reviewed code only. The checkout must be clean and the attestation must bind the exact final committed HEAD after the plan move, documentation commits, and all fixes. Keep the private key and state owner-private outside the checkout and never read or print secrets.

Before signing or publishing screenshot evidence, fetch `origin/main` and run `git diff --exit-code origin/main -- .github/local-validation/recipe.json .github/local-validation/policy.json .github/local-validation/registry.json`. Stop if any differ: checkout-relative inputs are trusted only after this check. A PR changing the trust inputs must first get those changes reviewed and landed through the trusted default-branch process.

The qualified push may happen before or after the local run, but before posting verify that local HEAD, the remote branch, and the pull request head all equal the signed SHA. Use the documented `local-validation post` command when this workflow or the user authorizes posting; never fabricate a receipt from logs or raw test results and never post the status manually. After posting a successful mobile E2E attestation, publish both final-run screenshots with `scripts/local-validation/post-screenshots.sh --post` using the same attestation digest, retained state directory, pinned AgentSCM binary, and iOS/Android artifact directories. Follow the exact invocation in `docs/local-e2e.md`. This is required for every PR with mobile E2E evidence, including CI migrations; `/pr` authorizes the upload and PR comment without another confirmation. Verify that the comment contains both images and binds the current PR head and attestation. A new attested head requires matching screenshots; never reuse screenshots from another run or commit.

Screenshot publication is part of completing PR delivery, not an optional follow-up. If credentials, artifacts, or upload services are unavailable, report the blocker and leave screenshot delivery outstanding; do not call the PR fully qualified or ready to merge. Do not rerun passing suites just to republish retained valid artifacts. For policy-exempt PRs without a mobile run, state that screenshots are not applicable rather than inventing evidence or running unnecessary mobile suites.

Do not run a duplicate broad suite immediately before the producer: its trusted recipe already owns the serial `bun run e2e:ios` then `bun run e2e:android` run. A valid receipt remains usable across an unrelated base fast-forward when its bound merge-base and other context are unchanged. Describe `agentscm/local-validation` as worker-asserted coverage with the limitations in `docs/local-e2e.md`, not as GitHub-run mobile testing or a currently enforced required check unless the live ruleset was verified.

### 8. Register and report

Immediately register the full PR URL with the host thread when a PR-link tool is available. Report the URL, pushed SHA, qualification evidence, signed SHA, attestation and screenshot-comment URLs when applicable (or the explicit screenshot blocker/not-applicable reason), and any disclosed unverified behavior.
