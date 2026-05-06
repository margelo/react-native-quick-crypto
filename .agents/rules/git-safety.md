# Git Safety Rules

## Blocking

- Never use `--no-verify` or `-n` with `git commit`.
- Never use `--no-verify` with `git push`.
- If hooks fail, fix the underlying issue.
- Use a 120000ms timeout for `git commit`; hooks run lint-staged, clang-format, tsc, and bob build.
- Never commit on `main`.
- Before committing, check the current branch.
- If on `main`, create `feat/`, `fix/`, or `refactor/` branch first.

## Strict

- Run `clang-format -i` on modified `.cpp`, `.hpp`, and `.h` files before staging.
- Run Prettier on modified `.ts` and `.tsx` files before staging.
- Run type checks before committing.
