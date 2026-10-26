# /pr - Create or Update a Pull Request

Create or update the PR for the current branch. Invoking `/pr` authorizes the qualified push required for this workflow.

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

### 7. Register and report

Immediately register the full PR URL with the host thread when a PR-link tool is available. Report the URL, pushed SHA, qualification evidence, and any disclosed unverified behavior.
