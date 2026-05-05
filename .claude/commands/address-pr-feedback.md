# /address-pr-feedback - Address PR Feedback

Fetch and address all review bot feedback on the current PR.

## Instructions

### 1. Identify the PR

```bash
gh pr view --json number,url,state --jq '{number, url, state}'
```

If no PR exists for the current branch, abort with a message.

### 2. Check that review bots are done

CodeRabbit reviews asynchronously. Before addressing feedback, verify it has finished.

```bash
# Get all reviews on the PR
gh pr view --json reviews --jq '.reviews[] | {author: .author.login, state: .state}'

# Check PR comments for bot activity (MUST use --paginate for large PRs)
gh api "repos/{owner}/{repo}/pulls/{pr}/comments" --paginate \
  --jq '[.[] | .user.login] | unique'
```

**CodeRabbit**: Look for a PR comment containing "Walkthrough" or a review with `coderabbitai[bot]` as author. If not present, inform the user:

> "CodeRabbit hasn't reviewed this PR yet. Wait for its review or run `@coderabbitai review` as a PR comment, then re-run this command."

**If the bot hasn't finished, stop here.** Do not proceed to fixing issues with incomplete feedback.

### 3. Fetch ALL review comments

**CRITICAL**: Always use `--paginate` with `gh api` for review comments. The default page size is 30, which is easily exceeded when CodeRabbit posts 16+ inline comments plus replies. Without `--paginate`, you will miss comments from later review passes.

#### 3a. Inline review comments

```bash
# Get ALL review comments — MUST use --paginate
gh api "repos/{owner}/{repo}/pulls/{pr}/comments" --paginate --jq '.[] | {
  id: .id,
  author: .user.login,
  path: .path,
  line: .line,
  body: .body,
  in_reply_to_id: .in_reply_to_id,
  created_at: .created_at
}'
```

To identify **new unaddressed root comments**, filter by:

- `in_reply_to_id == null` (root comment, not a reply)
- `user.login == "coderabbitai[bot]"`
- No reply from the PR author (`gh pr view --json author --jq '.author.login'`) exists with matching `in_reply_to_id`

Useful shortcut to see how many batches exist:

```bash
gh api "repos/{owner}/{repo}/pulls/{pr}/comments" --paginate \
  --jq '.[] | select(.user.login == "coderabbitai[bot]") | select(.in_reply_to_id == null) | .created_at' \
  | sort | uniq -c | sort -rn
```

Each unique timestamp cluster represents one review pass.

#### 3b. Outside-diff-range comments (in review body)

CodeRabbit posts "outside diff range" comments in the **review body**, not as inline comments. These are easy to miss.

```bash
# Get ALL CodeRabbit reviews with non-empty bodies (includes CHANGES_REQUESTED and COMMENTED states)
gh api "repos/{owner}/{repo}/pulls/{pr}/reviews" --paginate \
  --jq '.[] | select(.user.login == "coderabbitai[bot]") | select(.body | length > 0) | {id: .id, state: .state, submitted_at: .submitted_at}'
```

Then fetch each review body:

```bash
gh api "repos/{owner}/{repo}/pulls/{pr}/reviews/{review_id}" --jq '.body'
```

Look for the `<summary>⚠️ Outside diff range comments (N)</summary>` section in the body. Parse these — they contain file paths, line numbers, and the same comment format as inline comments.

Also look for these sections in review bodies:

- **"🧹 Nitpick comments (N)"** — valid code quality items
- **"♻️ Duplicate comments (N)"** — re-raised from prior reviews
- **"🤖 Prompt for AI Agents"** — structured fix instructions

#### 3c. General PR comments

```bash
gh api "repos/{owner}/{repo}/issues/{pr}/comments" --paginate \
  --jq '.[] | {id: .id, author: .user.login, body: .body, created_at: .created_at}'
```

### 4. Identify actionable feedback

Collect ALL comments from:

- Inline review comments (3a)
- Outside-diff-range / nitpick / duplicate comments from review bodies (3b)
- General PR comments (3c)

Filter to unaddressed items from `coderabbitai[bot]`.

**Before applying any fix**, first verify the finding against the current code and decide whether a code change is actually needed. If the finding is not valid or no change is required, do not modify code for that item and briefly explain why it was skipped.

For each comment, determine:

1. **Valid concern** — fix it
2. **False positive** — reply explaining why
3. **Stale** — code was already changed/removed since the comment was posted
4. **Ambiguous** — ask the user which direction to take

### 5. Present decisions for approval

**STOP and present a table** before making any changes. The user must approve the plan first.

| #   | Source          | File:Line            | Comment Summary              | Decision              | Rationale         |
| --- | --------------- | -------------------- | ---------------------------- | --------------------- | ----------------- |
| 1   | CR inline       | `path/to/file.ts:42` | Brief summary of the comment | Fix / Dismiss / Stale | Why this decision |
| 2   | CR nitpick      | `path/to/file.ts:10` | Brief summary                | Fix / Dismiss / Stale | Why               |
| 3   | CR outside-diff | `path/to/file.ts:78` | Brief summary                | Fix / Dismiss / Stale | Why               |

Wait for the user to:

- **Approve all** — proceed with all decisions as proposed
- **Override specific rows** — change the decision for individual items (e.g., "dismiss #3 instead of fixing")
- **Ask questions** — clarify any items before approving

**Do not proceed to step 6 until the user approves.**

### 6. Apply fixes locally (do NOT reply to bots yet)

**CRITICAL — DO NOT reply to bot threads in this step.** Bot replies must happen _after_ push so the bot can verify against the actual remote. Replying with "Fixed" before the commit is on the remote causes the bot to re-flag the comment as unfixed (it reads the remote, not your working tree).

For each item that needs a code change:

1. Read the file and understand the context around the flagged line.
2. Apply the fix.

Do not post any thread replies, PR comments, or "Fixed" messages yet. Just edit code.

### 7. Run quality gates

After all fixes are applied:

```bash
bun tsc
```

All must pass before committing.

### 8. Commit and push

If any code changes were made:

```bash
git add <specific files>
git commit -m "fix: address PR review feedback from CodeRabbit"
git push
```

**Verify the push landed before moving on.** Confirm `git log origin/<branch> -1` matches your local HEAD, or check `gh api repos/{owner}/{repo}/pulls/{pr} --jq .head.sha`. The bots will read this SHA when re-evaluating, so the reply in step 9 must reference code that is actually on it.

### 9. Reply to bot threads

Now that the fix is on the remote, post replies. Reference the new commit SHA in "Fixed" replies so the bot can verify and so the timeline is auditable later.

**Reply rules:**

1. **Inline review comments (3a)** — reply on the conversation thread:

   ```bash
   gh api "repos/{owner}/{repo}/pulls/{pr}/comments/{comment_id}/replies" \
     -X POST -f body="@coderabbitai Fixed in <sha> — <brief explanation>"
   ```

2. **Review-body / outside-diff items (3b)** — no inline thread exists. Post a top-level PR comment:

   ```bash
   gh pr comment {pr} --body "@coderabbitai Addressed in <sha>:
   - Fixed: <list of fixes with file:line references>
   - Dismissed: <list with reasoning>"
   ```

3. **General PR comments (3c)** — issue comments don't support threaded replies. Post a new PR comment referencing the original:
   ```bash
   gh pr comment {pr} --body "@coderabbitai Re: comment {comment_id} — Fixed in <sha> — <explanation>"
   ```

**CodeRabbit replies MUST start with `@coderabbitai`** or the bot will not see them.

For false positives / stale, use the same reply mechanism with an explanation instead of "Fixed":

```bash
gh api "repos/{owner}/{repo}/pulls/{pr}/comments/{comment_id}/replies" \
  -X POST -f body="@coderabbitai <explanation of why this is safe / stale>"
```

### 10. Report summary

Present a summary to the user:

- **Fixed**: List of issues that were fixed with brief descriptions
- **Dismissed**: List of false positives with reasoning
- **Stale**: Comments on code that was already changed/removed
- **Needs input**: Any ambiguous items requiring user decision
- **Quality gates**: Pass/fail status
