# /review - Code Review Branch Commits

Review all commits on the current branch since diverging from main.

## Instructions

When activated, perform a full code review of the commits since branching from main:

1. **Get the commits**: Run `git log main..HEAD --oneline` to see all commits on this branch
2. **Get the full diff**: Run `git diff main..HEAD` to see all changes
3. **For each file changed**, read enough context to understand the changes
4. **Review for**:
   - Correctness and logic errors
   - Consistency with existing patterns in the codebase
   - TypeScript best practices
   - C++ best practices (if touching native code)
   - Cryptographic correctness (if touching crypto code)
   - Potential bugs or edge cases
   - Missing error handling
   - Code clarity and maintainability
5. **Provide a structured review** with:
   - Summary of what the branch does
   - Positives (what's done well)
   - Issues & suggestions (ranked by severity)
   - Recommended actions (if any)

Run `bun tsc` to verify the code compiles.
