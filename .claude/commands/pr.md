# /pr - Create Pull Request

Create a pull request for the current branch.

## Instructions

When activated, create a pull request for the current branch:

1. **Verify branch state**:
   - Run `git branch --show-current` to get the current branch name
   - Ensure we're not on `main` (abort if so)
   - Run `git log main..HEAD --oneline` to see commits to include

2. **Push the branch** (if not already pushed):
   - Run `git push -u origin <branch-name>`

3. **Check for related issues**:
   - Look at the branch name for issue numbers (e.g., `fix/896-buffer-import` references #896)
   - Check commit messages for issue references
   - Run `gh issue list --state open --limit 20` to see recent open issues that might be related
   - If the PR resolves an issue, note it for the body

4. **Generate PR title and body**:
   - Title: Use conventional commit format based on the primary change (e.g., `fix: import Buffer from react-native-quick-crypto`)
   - Body should include:
     - **Summary**: Brief description of what this PR does
     - **Changes**: Bullet list of key changes
     - **Testing**: How to test the changes (if applicable)
     - **Issue references**: Add `Fixes #XXX` or `Closes #XXX` for any issues this PR resolves (these will auto-close the issues when merged)

5. **Create the PR**:
   ```bash
   gh pr create --title "<title>" --body "<body>" --base main
   ```

6. **Report the PR URL** to the user

If the user provides arguments (e.g., `/pr "Custom title"`), use that as the PR title instead of generating one.
