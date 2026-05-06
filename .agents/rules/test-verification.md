# Test Verification Rules

## Strict

Tests run only in the example React Native app. For runtime changes the assistant cannot fully validate, commit locally and wait for the user to run `bun ios` or `bun android` and exercise the relevant suite before pushing.

## Applies When

- C++ changes need the example app.
- Behavior changes are covered by example-app tests.
- New example-app tests were added and not run.
- A previous pushed fix failed user validation.

## Do Not Push Until

- User explicitly confirms tests pass, all green, ship it, or equivalent.
- If tests fail, add follow-up commits locally and keep waiting.
- Once confirmed, push all validated commits together.

## Exceptions

- Pure docs, plans, or `.agents/` config changes.
- User explicitly says to push/ship now.
- First PR push from an unpushed branch; still ask first if unverified runtime changes are included.
