# /implement - Implement an Issue End-to-End

Take one GitHub issue from recon through an open PR with minimal human intervention. `$ARGUMENTS` is a bare issue number, `#N`, or a full issue URL. With no argument, ask for the issue and stop.

Invoking `/implement` explicitly authorizes the qualified push and PR creation or update at the end of this workflow. It does not authorize bypassing hooks, shipping known failures, overwriting unrelated work, or guessing through a structural product decision.

## 1. Read the issue

Use the issue API rather than search snippets:

```bash
gh issue view <N> --json number,title,body,labels,comments,state,closedByPullRequestsReferences
```

Normalize the returned number. If the issue is closed or already has a closing PR, stop and report it. Derive a lowercase, hyphenated slug of at most five words and use the exact `<N>-<slug>` identifier for both the branch and plan.

## 2. Fresh recon

Use one fresh Astra recon subagent. Give it the complete issue text and comments plus the actual repository root returned by:

```bash
git rev-parse --show-toplevel
```

Recon must read `AGENTS.md`, the relevant `.agents/rules/*.md`, Node.js `$REPOS/node/deps/ncrypto` before new crypto implementation, and the actual files it cites. It must not edit.

Require the report to include:

1. Verified files and line anchors, with each claim based on opening the file.
2. Existing repository patterns to mirror.
3. Two to five independently committable phases and their dependencies.
4. Targeted tests and affected toolchains.
5. Native platforms and driveable example-app checks.
6. Structural questions only.
7. Security and compatibility risks.
8. Explicitly unverified claims.

Recount issue-provided file lists or quantities instead of trusting them. Mark inference as inference. If recon finds no change to make, stop and report.

## 3. Resolve structural forks once

Ask before code only when a wrong answer would discard substantial work: an API contract, a new cross-layer shape, a user-visible behavior the issue does not define, or designs with materially different security or compatibility impact. Present two or three concrete options with the recommendation first.

Naming, file placement, factoring, and choices established by repository patterns are not structural questions. After this point, record reasonable decisions under **Assumptions** and continue. If a late discovery truly invalidates the chosen structure, stop and report rather than layering work onto it.

## 4. Guard the checkout and create the tracker

Before creating a branch:

```bash
git status --porcelain
git rev-parse --show-toplevel
git fetch origin main
git show-ref --verify --quiet refs/heads/<type>/<N>-<slug>
```

The working tree must be clean. Do not stash or absorb unrelated edits. Confirm the real repository root and stop if the branch already exists. Create `<type>/<N>-<slug>` from `origin/main`, where type is `fix`, `feat`, or `refactor`.

Run `mkdir -p plans/todo`, then create `plans/todo/<N>-<slug>.md` with:

- Problem and intended outcome.
- **Live tracker** checklist for every implementation, qualification, review, and delivery phase.
- **Decisions** for user-selected structural choices.
- **Assumptions** for non-structural choices made during execution.
- **Evidence** entries containing commit SHA, exact tool or test, result, and platform.
- **Unverified** items with the condition that would settle each one.

Point the ignored `.agents/progress/claude-progress.md` stub at the active plan and commit the plan. Never manufacture a retroactive tracker for an already-running branch merely to claim this workflow was followed.

## 5. Implement sequentially with fresh context

Run each dependent phase in order with one fresh Sol subagent at default reasoning. Parallelize only early work that is structurally independent and cannot overlap files or assumptions.

Each phase prompt must include the actual repo root, expected branch, the plan path, that phase only, relevant recon evidence, prior corrections, applicable rules, and the targeted verification policy. Require the phase agent to:

1. Confirm the repository root and branch before editing.
2. Re-open every file and verify recon claims.
3. Implement only its assigned phase.
4. Add or update tests selected by changed behavior and dependencies.
5. Run affected checks without repeating still-current evidence.
6. Update the plan tracker, decisions, assumptions, and evidence.
7. Stage only its files and make a conventional commit through the real hooks.
8. Return changed paths, commit SHA, exact checks and platforms, deviations, and unfinished work.

After every phase, independently verify:

```bash
git rev-parse HEAD
git status --porcelain
```

The SHA must have advanced and the tree must be clean. If the phase fails to commit, leaves changes, or reports unverified required behavior, retry once with a fresh Sol reviewer-tier subagent at high reasoning using the failure output and first report. Stop after the second failure.

When a phase corrects recon, update the plan and all later prompts. Do not propagate a disproven premise.

## 6. Qualify the branch

Select checks from the actual diff and reuse valid phase evidence keyed by SHA, tool or test, and platform.

- Run relevant TypeScript, lint, formatting, generated-code, C++, OpenSSL, and native checks for every changed toolchain.
- Run `cd packages/react-native-quick-crypto && bun run test` only when actual Node-side code changed. Do not substitute bare `bun test`.
- Test native runtime behavior in the example app. Attach to an existing RNQC app and Metro first; do not restart another project or take over its port. Use `/tmp/rnqc-metro.log` for RNQC Metro diagnostics.
- Build and install the example app when a native change requires a rebuild. Drive the affected tests or flow when feasible and record the platform.
- Do not rerun broad suites per phase. A full foundational shared-crypto suite requires a stated cross-cutting reason or unexplained failure, one owner, and one reusable result.
- Documentation-only changes need link and consistency checks, not a runtime retest.

A missing credential, unavailable platform, or unverified behavior blocks delivery only when a failure could require changing the diff. Stop and state the exact check needed. If the user explicitly directs shipment, disclose the unverified behavior and residual risk in the PR.

Qualification fixes go to a fresh Sol implementation subagent and must be committed. Retry at most twice.

## 7. Independent local review

Use a fresh reviewer that did not implement the branch: Sol at high reasoning for general review, or Astra for focused difficult crypto correctness review. Follow `.agents/commands/review.md`, including `git fetch origin`, the `origin/main...HEAD` diff, uncommitted state, and every changed toolchain.

Classify findings as Fix, Skip, or Ask. Apply clear Fix items immediately and continue independent fixes. Under `/implement`, do not add another approval round: resolve Ask items from the issue, code, and established decisions when possible and record the result under **Assumptions**. Stop only for a genuine unresolved structural choice. Commit review fixes and rerun only invalidated checks.

Local review is required even if a review bot exists; it never waits for a bot.

## 8. Complete the plan before the PR

When implementation, qualification, and local review are complete, move the exact tracker in the same branch:

```bash
mkdir -p plans/done
git mv plans/todo/<N>-<slug>.md plans/done/<N>-<slug>.md
rm -f .agents/progress/claude-progress.md
```

Carry any genuinely outstanding verification item with an owner and disclosure. Commit the plan move before opening the PR. If more than one plan could match, move none and stop for disambiguation. Work that is not implemented remains in `plans/todo/`.

## 9. Finish with /pr

Read and execute `.agents/commands/pr.md` completely. Recompute scope, verification, and delivery from the actual diff rather than recon. Use `Closes #<N>`, push the qualified commits, reuse an existing PR for the branch when present, and create one otherwise.

If the host exposes a PR-link registration tool, register the full PR URL with the current thread immediately after creating or taking ownership of the PR.

## Final report

Keep the report concise: changed behavior, PR URL or exact blocker, independent review findings and dispositions, assumptions, verification evidence by SHA/tool/platform, and explicitly unverified residue.
