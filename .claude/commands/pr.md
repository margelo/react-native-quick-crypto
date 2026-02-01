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

3. **Generate PR title and body**:
   - Title: Use conventional commit format based on the primary change (e.g., `fix: import Buffer from react-native-quick-crypto`)
   - Body should include:
     - **Summary**: Brief description of what this PR does
     - **Changes**: Bullet list of key changes
     - **Testing**: How to test the changes (if applicable)
     - Reference any related issues with `Closes #XXX` or `Fixes #XXX`

4. **Create the PR**:
   ```bash
   gh pr create --title "<title>" --body "<body>" --base main
   ```

5. **Report the PR URL** to the user

If the user provides arguments (e.g., `/pr "Custom title"`), use that as the PR title instead of generating one.
