# Commit Changes

Stage and commit the current changes with a well-crafted message.

## Instructions

When activated, commit the current working tree changes:

1. **Sync with remote**:
   - Run `git fetch origin main` to get latest upstream
   - Run `git log HEAD..origin/main --oneline` to check if main has moved ahead
   - If it has, warn the user but don't rebase automatically

2. **Ensure we're not on main**:
   - Run `git branch --show-current`
   - If on `main`, create a new feature branch:
     - Look at the staged/unstaged changes to infer a branch name
     - Run `git checkout -b feat/<descriptive-name>`
     - Inform the user of the new branch name

3. **Review changes**:
   - Run `git diff --stat` and `git diff --staged --stat` to see what's changed
   - If nothing is staged, run `git add -A` to stage everything
   - Run `git diff --staged --stat` to confirm what will be committed

4. **Run code quality checks before committing**:
   - **C++ files**: If any `.cpp`/`.hpp`/`.h` files are staged, run:
     ```bash
     clang-format -i <files>
     ```
     Then re-stage them with `git add`.
   - **TypeScript files**: If any `.ts`/`.tsx` files are staged, run:
     ```bash
     npx prettier --write <files>
     ```
     Then re-stage them with `git add`.
   - **Type check**: Run `cd packages/react-native-quick-crypto && bun tsc --noEmit` to verify types.

5. **Generate commit message**:
   - Use conventional commit format: `type: short description`
   - Types: `feat`, `fix`, `refactor`, `chore`, `docs`, `test`
   - If the change is substantial, add a body paragraph separated by a blank line
   - Body should explain **what** changed and **why**, not how (the diff shows how)
   - Keep the subject line under 72 characters

6. **Commit** (with 120000ms timeout — pre-commit hooks run lint-staged, clang-format, tsc, and bob build):
   ```bash
   git commit -m "<message>"
   ```
   **NEVER use `--no-verify`.** Pre-commit hooks exist to catch errors. If they fail, fix the issue.

7. **Report** the commit hash and summary to the user

If the user provides arguments (e.g., `/commit "fix: resolve race condition"`), use that as the commit message instead of generating one.
