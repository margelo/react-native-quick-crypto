# /review - Code Review Branch Commits

Review all commits on the current branch since diverging from main.

## Prerequisites

**IMPORTANT**: A reviewer should not be the same "person" who wrote the code. Before starting, check if this is a fresh context/session:

- **If there is prior conversation history in this session** (e.g., you helped write the code being reviewed), do NOT review it yourself — your context is biased. Instead, spawn a fresh reviewer:
  - Launch a subagent (synchronously — `run_in_background: false`) with a prompt telling it to perform the full review defined in the **Instructions** section below on the current branch, and to return its findings as: a summary, positives, and a severity-ranked list of issues (each with `file:line`, description, and a proposed action). Paste the Instructions criteria into the prompt so the subagent doesn't need to re-read this file.
  - Pick the subagent type by what the diff actually touches: `crypto-specialist` for crypto/algorithm changes, `cpp-specialist` for `cpp/`, `typescript-specialist` for TS-only changes, `general-purpose` otherwise. Spawn more than one in parallel when the diff spans domains.
  - **Scope the prompt to THIS branch's actual changes, not the generic template.** Before spawning, run `git diff --stat origin/main..HEAD` and put the concrete context into the prompt: what the branch does, which subsystem it touches (this repo spans C++/OpenSSL under `packages/react-native-quick-crypto/cpp`, the TypeScript package under `src/`, the Expo config plugin, the `example/` RN app and its test suites, `docs/`, and CI workflows — name the ones actually changed), and the list of changed files. Tell the subagent to open and review **every** changed file, including non-C++ ones (`.ts`, `.tsx`, podspec, Gradle, `.github/workflows`, `.agents/`), and to validate **each** changed toolchain rather than assuming one check covers the diff.
  - The subagent starts with a clean context and did NOT write the code, so its review is unbiased.
  - When it returns, relay its review to the user verbatim, then run the **Follow-up** fix-plan step yourself (the subagent can't interact with the user).
- **If this is a fresh context** (no prior history — you did not write this code), perform the review directly.

## Instructions

When activated, perform a full code review of the commits since branching from main:

1. **Sync the base**: Run `git fetch origin` first. Local `main` is often stale (a PR merged upstream but not pulled locally), which silently drags already-merged commits into the review scope and balloons the diff. Use `origin/main` as the base for everything below.
2. **Get the commits**: Run `git log origin/main..HEAD --oneline` to see all commits on this branch
3. **Get the full diff**: Run `git diff origin/main..HEAD` to see all changes
4. **For each file changed**, read enough context to understand the changes
5. **Review for**:
   - Correctness and logic errors
   - Consistency with existing patterns in the codebase
   - TypeScript best practices
   - C++ best practices (if touching native code)
   - Cryptographic correctness (if touching crypto code)
   - Potential bugs or edge cases
   - Missing error handling
   - Code clarity and maintainability
6. **Provide a structured review** with:
   - Summary of what the branch does
   - Positives (what's done well)
   - Issues & suggestions (ranked by severity)
   - Recommended actions (if any)

Verify the toolchains the diff actually touches: `bun tsc` for TypeScript, `bun test` (in `packages/react-native-quick-crypto`) if node-side tests changed, `clang-format --dry-run --Werror` for C++. C++ runtime behavior and example-app test suites can only be validated by the user running `bun ios` / `bun android` — flag that rather than claiming it passes.

## Follow-up

After presenting the review, present a **fix plan table** for the user to approve before making any changes:

| #   | Severity | File:Line          | Issue             | Proposed Action  |
| --- | -------- | ------------------ | ----------------- | ---------------- |
| 1   | Medium   | path/to/file.ts:42 | Brief description | Fix / Skip / Ask |

- **Fix**: Will apply the change
- **Skip**: Not worth changing (explain why)
- **Ask**: Ambiguous, needs user input on approach

**Wait for the user to approve the plan** (they may want to skip or modify items). They may reply with "approve" / "approve all" to accept everything, override individual rows ("skip #3", "fix #5 differently"), or ask clarifying questions.

Once approved, apply only the approved fixes, then re-run the same toolchain checks to verify everything is clean.

Then commit the approved fixes (via `/commit`) — don't leave review changes sitting in the working tree.
