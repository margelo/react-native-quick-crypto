# /review - Review Branch Changes

Review every branch change since the merge base with current `origin/main`, including uncommitted work.

## Independence

The reviewer must not be the agent that wrote the changes. If this session implemented or materially shaped the diff, use one fresh reviewer: Sol at high reasoning for general work or Astra for a focused difficult crypto-correctness review. Give it the actual changed-file list, applicable rules, and current verification evidence. Do not create extra reviewers unless the diff has genuinely independent domains that one reviewer cannot cover well.

Local review is required and is not contingent on CodeRabbit or any other bot existing or finishing.

## Instructions

### 1. Establish accurate scope

```bash
git fetch origin
git log origin/main..HEAD --oneline
git diff --stat origin/main...HEAD
git diff --name-only origin/main...HEAD
git diff origin/main...HEAD
git status --short
git diff
git diff --staged
```

Use two dots for the commit list and three dots for the branch diff. Treat uncommitted and staged changes as part of the review and label findings that apply to them.

### 2. Read every changed file

Open every changed file with enough surrounding context to understand the behavior. Include TypeScript, C++, Nitro specifications/generated bindings, package metadata, podspec/Gradle/CMake, example-app tests, scripts, CI, documentation, and `.agents/` files when present.

Review for:

- Correctness, edge cases, and error handling.
- Consistency with existing repository patterns.
- WebCrypto and Node.js compatibility.
- Nitro boundary and generated-code consistency.
- TypeScript strictness and public API shape.
- C++20 ownership, RAII, and memory safety.
- OpenSSL 3.6+ EVP/provider usage and checked return values.
- Cryptographic correctness, constant-time behavior, secret handling, nonce discipline, and authoritative vectors.
- Build, packaging, and platform-specific delivery impact.
- Test adequacy and whether evidence covers the current SHA.

### 3. Verify each changed toolchain

Reuse evidence only when it names the commit SHA, exact tool or test, result, and platform, and no relevant later edit invalidated it. Request or run missing scoped checks.

- TypeScript: relevant `bun tsc`, lint, and formatting checks.
- C++: `clang-format --dry-run --Werror` over the changed native scope plus relevant compile or OpenSSL checks.
- ncrypto/OpenSSL: `scripts/check-ncrypto-openssl-deprecations.sh` when applicable.
- Node-side code: `cd packages/react-native-quick-crypto && bun run test`. Run this only for actual Node-side changes; never use bare `bun test` as a substitute.
- Native runtime: build, install, and exercise the affected example-app behavior on the relevant iOS or Android platform when feasible. For targeted debugging, attach to an existing RNQC app and Metro first and use `/tmp/rnqc-metro.log`. For canonical full-app coverage, use the root `bun run e2e:ios` then `bun run e2e:android` flow documented in `docs/local-e2e.md`; its runner owns the app, device, isolated Metro port, and cleanup.
- Docs-only: validate links, paths, command names, and repository claims; do not rerun runtime suites.

Do not repeat a broad suite merely because review started. A full foundational shared-crypto suite needs a stated cross-cutting reason or concrete unexplained failure, one owner, and a reusable result.

Review may reuse current raw E2E evidence even before final attestation. Do not treat logs or raw results as a signed merge-gate receipt. After all review fixes and documentation or plan commits, delivery must attest the exact final clean committed HEAD with the trusted inputs and pinned patched producer described in `docs/local-e2e.md`. Do not claim GitHub ran the device suites or that the status context is currently required unless live ruleset verification proves it.

### 4. Report findings

Return:

1. Summary of the branch.
2. Positives.
3. Severity-ranked findings with `file:line`, impact, evidence, and proposed action.
4. Verification coverage and explicit gaps.

Then print the decision table before editing:

| # | Severity | File:Line | Finding | Decision | Rationale |
|---|---|---|---|---|---|
| 1 | Medium | `path/file.ts:42` | Brief finding | Fix / Skip / Ask | Why |

- **Fix:** A validated issue with a clear repository-consistent correction.
- **Skip:** Not valid, stale, already covered, or not worth changing; explain why.
- **Ask:** Two defensible choices lead to materially different behavior or blast radius and the repository cannot decide.

Apply every clear Fix immediately after printing the table. Do not wait for approval when there are no Ask items. If Ask items exist, apply independent Fix items and run their checks before asking only the genuine choices. Never turn naming, factoring, or a discoverable convention into an Ask.

When `/review` is called from `/implement`, `/implement` owns the follow-through and no additional approval round is added.

After fixes, rerun only invalidated scoped checks and commit them through `/commit`. Never push unless the user invoked a workflow that authorizes it.
