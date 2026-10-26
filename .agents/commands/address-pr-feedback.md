# /address-pr-feedback - Address PR Feedback

Fetch, validate, and resolve all unaddressed feedback on the current PR. Invoking this workflow authorizes replies, the commits needed for fixes, and the qualified push of those commits. Do not reply to PR feedback outside an explicitly invoked feedback workflow.

Do not require CodeRabbit or any other reviewer to exist or finish. Process the feedback that is present; local `/review` remains independent.

## 1. Identify and register the PR

```bash
gh pr view --json number,url,state,author,headRefName,headRefOid --jq '{number,url,state,author,headRefName,headRefOid}'
```

Abort if the branch has no open PR. Register its URL with the host thread if a PR-link tool is available.

Capture the number:

```bash
PR=$(gh pr view --json number --jq .number)
```

## 2. Fetch all three feedback sources

Always paginate every endpoint. These are separate datasets and none substitutes for another.

### Inline review comments and replies

```bash
gh api "repos/{owner}/{repo}/pulls/$PR/comments" --paginate --jq '.[] | {
  id,
  author: .user.login,
  path,
  line,
  body,
  in_reply_to_id,
  commit_id,
  created_at
}'
```

### Review bodies

```bash
gh api "repos/{owner}/{repo}/pulls/$PR/reviews" --paginate --jq '.[] | {
  id,
  author: .user.login,
  state,
  body,
  commit_id,
  submitted_at
}'
```

Read every non-empty review body. Findings outside the diff, summaries, and multi-item reviews often exist only here.

### General PR comments

```bash
gh api "repos/{owner}/{repo}/issues/$PR/comments" --paginate --jq '.[] | {
  id,
  author: .user.login,
  body,
  created_at
}'
```

Identify unaddressed root findings. An inline entry with `in_reply_to_id != null` is a reply, not a new root. Account for existing author replies so reruns do not process settled threads or the workflow's own prior replies as findings.

## 3. Validate every claim

Open the current file and enough context to verify the comment's mechanism and conclusion. Compare the comment's commit to current HEAD when staleness matters. A confident reviewer comment is evidence to investigate, not ground truth.

Classify each item:

1. **Fix:** Valid and has a clear repository-consistent correction.
2. **Dismiss:** Incorrect, out of scope, or no change is warranted; explain the evidence.
3. **Stale:** Current code already resolves or removes the concern.
4. **Ask:** Two defensible responses materially change behavior or blast radius and repository evidence cannot decide.

Use Ask only for genuine user-choice ambiguity. Resolve naming, factoring, and discoverable conventions autonomously.

## 4. Print decisions, then act

Print:

| # | Source | File:Line | Summary | Decision | Rationale |
|---|---|---|---|---|---|
| 1 | Inline / Review body / General | `path:42` | Brief claim | Fix / Dismiss / Stale / Ask | Verified reason |

If there are no Ask rows, immediately execute every decision without waiting. If Ask rows exist, continue all independent Fix, Dismiss, and Stale items through verification, push when needed, and replies; then ask only the unresolved choices.

## 5. Fix, gate, commit, push, verify SHA

The order is mandatory:

**fix → scoped gates → commit → push → verify remote SHA → reply**

Do not post early replies. For fixes:

1. Edit the validated scope.
2. Run checks selected by the changed behavior and affected toolchains.
3. Reuse still-current evidence and rerun only checks invalidated by the fix.
4. Run Node Jest only for actual Node-side changes with `cd packages/react-native-quick-crypto && bun run test`.
5. Build or drive the example app when native runtime behavior requires it; docs-only fixes need no runtime retest.
6. Stage explicit paths and commit through `/commit`.
7. Push normally, never with `--no-verify`.

Verify local and remote SHAs:

```bash
BRANCH=$(git branch --show-current)
LOCAL_SHA=$(git rev-parse HEAD)
REMOTE_SHA=$(git rev-parse "origin/$BRANCH")
PR_SHA=$(gh pr view "$PR" --json headRefOid --jq .headRefOid)
test "$LOCAL_SHA" = "$REMOTE_SHA"
test "$LOCAL_SHA" = "$PR_SHA"
```

If no code or documentation changed because every item is Dismiss or Stale, skip commit and push, use the current PR head SHA, and proceed to replies.

## 6. Reply after verification

Reference the verified SHA and concise evidence.

For inline roots, reply on the existing thread:

```bash
gh api "repos/{owner}/{repo}/pulls/$PR/comments" -X POST -f body="Fixed in <sha> — <explanation>" -F in_reply_to=<comment_id>
```

Use the same mechanism for Dismiss or Stale with the reason instead of claiming a fix.

Review-body findings have no inline thread. Post one consolidated top-level comment keyed to review IDs:

```bash
gh pr comment "$PR" --body-file <review-body-response-file>
```

General issue comments do not support review threading. Post a new PR comment that references the original comment ID:

```bash
gh pr comment "$PR" --body "Re: comment <id> — addressed at <sha> — <explanation>"
```

Do not require an `@coderabbitai` prefix unless that reviewer specifically requires it.

## 7. Report

Report Fixed, Dismissed, Stale, Needs input, checks with SHA/platform, pushed SHA, and reply status. If feedback changed PR scope or delivery, update the PR body through `--body-file`.
