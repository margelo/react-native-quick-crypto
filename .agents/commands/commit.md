# /commit - Commit Changes

Stage and commit only the current task's changes. Standalone `/commit` does not push.

## Instructions

### 1. Synchronize and guard the branch

```bash
git fetch origin main
git branch --show-current
git log HEAD..origin/main --oneline
git status --short
```

Never commit on `main`. If the task started on `main`, create a correctly named `feat/`, `fix/`, or `refactor/` branch before committing and report it. If `origin/main` moved ahead, report that fact but do not rebase automatically.

### 2. Define the commit scope

Review both staged and unstaged changes:

```bash
git diff --stat
git diff --staged --stat
git diff
git diff --staged
```

Preserve unrelated edits. Stage explicit task paths with `git add <path>...`; never default to `git add -A`. If ownership of a changed path is genuinely unclear, leave it unstaged and report it.

### 3. Run relevant pre-commit checks

Format and verify what the commit changes:

- C++ files: run `clang-format -i` on the explicit changed `.cpp`, `.cc`, `.cxx`, `.hpp`, and `.h` paths, then stage them again.
- TypeScript or JavaScript files: run the repository's Bun-backed Prettier/lint scripts for the affected workspace, then stage resulting task-file edits.
- TypeScript API or implementation: run the relevant `bun tsc`.
- Node-side behavior: run `cd packages/react-native-quick-crypto && bun run test` only when actual Node-side code changed.
- ncrypto/OpenSSL changes: run `scripts/check-ncrypto-openssl-deprecations.sh` and other affected native checks.
- Documentation-only changes: run link/path/command consistency checks and `git diff --check`; no runtime test is required. If this commit follows a native attestation, note that delivery needs a new receipt for the new final HEAD rather than treating the prior receipt as current.

Reuse current evidence when it covers the staged diff. Do not run a broad suite by default.

### 4. Confirm the index

```bash
git diff --staged --stat
git diff --staged
```

Abort if nothing is staged. Confirm no unrelated file entered the index.

### 5. Commit through mandatory hooks

Use a conventional message with a subject under 72 characters. If the user supplied a message, use it. A body should explain what and why.

```bash
git commit -m "<type>: <description>"
```

Allow at least 120 seconds. The tracked hook runs `bun lint-staged`, C++ `clang-format --dry-run --Werror`, `bun tsc`, and `bun --filter="react-native-quick-crypto" prepare`. Never use `--no-verify` or `-n`; fix failures and retry normally.

### 6. Report

Report the commit SHA, subject, staged paths, checks run, and any uncommitted paths deliberately left alone. Do not push unless a separately invoked workflow such as `/pr`, `/implement`, or `/address-pr-feedback` authorizes it.
