# Test Verification Rules

## Evidence standard

Select verification from the actual diff, changed behavior, and affected dependencies. Record reusable evidence with:

- Commit SHA.
- Exact command, tool, test, or driven flow.
- Result.
- Platform, simulator, or device when native behavior is involved.

Evidence remains current until a relevant edit or failure invalidates it. Reuse it across phases, review, commit, and PR preparation instead of repeating broad checks.

## Targeted checks

- TypeScript changes: relevant `bun tsc`, lint, and formatting checks.
- C++ changes: formatting plus affected compile, OpenSSL, native build, and runtime checks.
- ncrypto/OpenSSL compatibility: `scripts/check-ncrypto-openssl-deprecations.sh` when in scope.
- Actual Node-side implementation or test changes: `cd packages/react-native-quick-crypto && bun run test`. Bare `bun test` is Bun's runner and does not execute the package's Jest script.
- Native behavior: build, install, and exercise the affected example-app path on iOS or Android.
- Pure documentation, plans, and `.agents/` configuration: validate links, file paths, commands, and repository claims; no runtime retest.

Do not routinely run every test suite after each phase, commit, review, or documentation edit. A full foundational shared-crypto suite is appropriate only for a cross-cutting crypto/harness change or a concrete unexplained failure. State the reason before running it, assign one owner, and reuse the result while it remains current.

## Native app authority

Agents may run native builds, simulators or devices, app tests, and driven verification. A genuinely current successful result qualifies without a separate user passphrase or approval round.

Attach to an existing RNQC app and Metro first. Do not restart or kill another project's process and do not take over its port. If a native change requires rebuilding, use the example app's real scripts, such as `cd example && bun ios`, `bun android`, `bun run build:ios`, or `bun run build:android`, then run the relevant app flow. Full Maestro runners are `example/test/e2e/run-ios.sh` and `example/test/e2e/run-android.sh` when full-app coverage is justified.

RNQC Metro client logs are tee'd to `/tmp/rnqc-metro.log`. Diagnose failures with:

```bash
grep -E "FAIL|❌|failed" /tmp/rnqc-metro.log | tail -20
```

## Delivery boundary

Unverified runtime behavior blocks push or PR delivery when failure could require changing the diff. Missing credentials, unavailable hardware, or irreversible external actions qualify only when they affect that decision.

The user may explicitly direct shipment despite a gap. In that case, disclose the exact unverified behavior, affected platform, and residual risk in the handoff and PR. Do not describe it as passing.
