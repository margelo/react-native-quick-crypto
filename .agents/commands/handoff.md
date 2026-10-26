# /handoff - Session Handoff

Produce a concise, self-contained handoff so the next session can resume without trusting conversation history.

## Gather

Read the current branch, recent commits, working tree, linked issue or PR, and the exact active plan if one exists:

```bash
git branch --show-current
git log --oneline -10
git status --short
gh pr view --json number,url,state,title,headRefOid 2>/dev/null || true
```

Check `.agents/progress/claude-progress.md` and its referenced plan, but do not assume a stale or missing stub describes the branch.

## Output

Include only relevant sections:

- **State:** branch, HEAD SHA, clean or exact uncommitted paths, issue, PR URL/state/head SHA, and active plan phase.
- **Completed:** concrete work with commit SHAs or file paths.
- **Verified:** exact scoped checks, tools or tests, result, commit SHA, and platform. Distinguish native build, installed-app, simulator/device, Node-side, and documentation evidence.
- **Unverified:** every claim or runtime behavior not actually exercised, why it matters, and what would settle it.
- **Decisions:** non-obvious choices and rationale.
- **Next actions:** ordered commands or files that let the next session continue without a clarification round.
- **Sibling dependencies:** related repository branch, SHA, PR, unpublished change, or external dependency when relevant.

State whether subagent reports were independently checked. Do not report a test as current if relevant edits occurred after its recorded SHA. Do not hide failures or imply a push, PR update, device run, or review happened when it did not.
