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

For targeted interactive work, attach to an existing RNQC app and Metro first. Do not restart or kill another project's process and do not take over its port. If a native change requires rebuilding, use the example app's real scripts, such as `cd example && bun ios`, `bun android`, `bun run build:ios`, or `bun run build:android`, then run the relevant app flow.

For canonical full-app qualification, run `bun run e2e:ios` and then `bun run e2e:android` from the repository root. The wrappers invoke `example/test/e2e/runner.mjs`, which selects the configured platform target, creates and owns its RNQC simulator or emulator, uses an isolated Metro port, writes per-run evidence, and cleans up its resources. Do not point it at another project's app, reuse an overlapping server, or substitute a Maestro flow.

RNQC Metro client logs are tee'd to `/tmp/rnqc-metro.log`. Diagnose failures with:

```bash
grep -E "FAIL|❌|failed" /tmp/rnqc-metro.log | tail -20
```

## Delivery boundary

Unverified runtime behavior blocks push or PR delivery when failure could require changing the diff. Missing credentials, unavailable hardware, or irreversible external actions qualify only when they affect that decision.

The user may explicitly direct shipment despite a gap. In that case, disclose the exact unverified behavior, affected platform, and residual risk in the handoff and PR. Do not describe it as passing.

## Attested native qualification

When the native merge gate applies, `docs/local-e2e.md` is canonical. Produce the final attestation with the trusted recipe, policy, and registry from `main` and the documented pinned AgentSCM build. The signing key and state stay owner-private and outside the checkout; never read or print secrets.

Raw platform evidence may remain useful through review while no relevant edit invalidates it, but it is not the delivery attestation. The final attestation must cover the exact clean committed HEAD after every plan move, documentation commit, and fix, binding its tree, base ref, and merge-base. A later base fast-forward alone does not invalidate a receipt when the bound merge-base and other context remain unchanged.

The producer owns one serial iOS-then-Android recipe run; do not add a duplicate broad suite immediately beforehand. Never create an attestation from logs or raw test output, never post a status manually, and post the actual attestation only through the documented CLI when the active workflow or user authorizes posting. Before posting, verify the pull request remote head equals the signed SHA. Every PR with mobile E2E evidence must also publish both final-run screenshots through `scripts/local-validation/post-screenshots.sh --post`, bound to the same head and attestation. `/pr` authorizes this publication; no separate confirmation is needed. Missing screenshot publication is an outstanding delivery blocker. Policy-exempt PRs without mobile runs should report screenshots as not applicable.

`agentscm/local-validation` represents a signed AgentSCM `worker_asserted` record with the coverage and limitations documented in `docs/local-e2e.md`; it does not mean GitHub ran the mobile suites. Do not claim the context is enforced by branch protection unless the live ruleset has been verified; the documented rollout says it is not yet required.
