# React Native Quick Crypto - Agent Configuration

This project uses agent workflows for repository work. `AGENTS.md` and `.agents/` are canonical; `CLAUDE.md` and `.claude` are symlink aliases for tools that expect Claude-style paths.

## Slash command dispatch

When a user prompt begins with `/name`, read `.agents/commands/name.md` completely before planning or taking any task action, then follow it as the authoritative end-to-end workflow. The `.claude/commands/` path resolves to the same files through the `.claude` symlink.

If that exact command file is missing, search `.agents/commands/` for a documented alias and any known canonical source before acting. If none exists, flag the absence; do not silently invent a partial workflow from memory.

Load the repository rules relevant to the requested area. For command-style work, inventory `.agents/commands/` early so aliases and related workflows are not missed.

## Repository priorities

### API priority order (non-negotiable)

When implementing features, favor these sources in order:

1. WebCrypto API for modern `subtle.*` methods.
2. Node.js `$REPOS/node/deps/ncrypto` for `crypto.*` compatibility and implementation patterns.
3. `$REPOS/ncrypto` as the standalone ncrypto and OpenSSL reference.

Always inspect Node.js `deps/ncrypto` before implementing new crypto behavior, then adapt it to OpenSSL 3.6+ requirements.

### Required stack

- React Native.
- TypeScript in strict mode with no `any`.
- Nitro Modules for native bridging.
- C++20 or newer with smart pointers and RAII.
- OpenSSL 3.6+ EVP/provider APIs only.
- Bun 1.3+ for package management and scripts.

### Code philosophy

- Minimize code and avoid duplication.
- Prefer small, independently verifiable changes.
- Keep code self-documenting; comment only when the behavior is complex enough to require it.
- Preserve the existing crypto, Nitro, TypeScript, and C++ rules in `.agents/rules/`.

### Security

- Use constant-time comparisons such as `CRYPTO_memcmp()` for authentication material.
- Use `RAND_bytes()` and check its return value.
- Prefer authenticated encryption such as AES-GCM.
- Never expose key material in errors or logs.
- Validate against authoritative WebCrypto, Node.js, NIST, or RFC vectors as applicable.

## Branch and delivery safety

- Never commit on `main`; create a `feat/`, `fix/`, or `refactor/` branch first.
- Never use `--no-verify` for commits or pushes.
- Preserve unrelated working-tree changes and stage task files explicitly.
- All changes land through pull requests.
- Prefer linear history. Rebase feature branches and use squash or fast-forward integration; do not create merge commits unless explicitly requested. If rewriting a dependency commit changes its SHA, update its downstream pins.
- `/implement` is explicitly authorized to push a qualified branch and create or update its PR. `/pr` is explicitly authorized to make the qualified push needed to create or update the PR. Standalone `/commit` never pushes implicitly.

## Plans

New `/implement` work uses `plans/todo/<N>-<slug>.md` as the live tracker, including phases, decisions, assumptions, and verification evidence. Do not create a retroactive plan merely to make an already-running branch look as though it followed the workflow.

Before opening a PR for completed planned work, move the one exact matching plan to `plans/done/` in the same branch and PR. Carry genuinely outstanding verification items with an owner. Never fuzzy-match plan names. Remove the ignored `.agents/progress/claude-progress.md` stub when its plan moves so later sessions do not inherit stale state.

## Agent and model routing

- Bounded implementation and routine verification: Sol at its default reasoning effort.
- General independent review and an implementation retry: Sol at high reasoning effort.
- Initial `/implement` recon, difficult design, and focused crypto correctness review: Astra.
- Explicit user model choices and live provider capabilities override these defaults.
- Documentation selects models for delegated work; it does not switch the active thread's model.
- Do not silently invoke separately billed tools. Use no more agents than the work requires, avoid duplicate research, and keep handoffs concise.
- Use early parallel work only for genuinely independent structural discovery. Implementation phases that share files or assumptions run sequentially with fresh context and bounded retries.

## Verification agreements

- Select checks from the actual diff, changed behavior, and affected dependencies. Record reusable evidence with the commit SHA, exact tool or test, result, and platform.
- Reuse still-current evidence across phases, review, and PR preparation. Do not repeat a broad suite after every phase, review, documentation edit, or commit.
- A full foundational shared-crypto suite is justified only by a cross-cutting crypto/harness change or concrete unexplained failure. State the reason first, assign one owner, and reuse its result until relevant edits invalidate it.
- TypeScript changes use the relevant `bun tsc`, lint, and formatting scripts.
- Run the package Jest suite only for actual Node-side code changes: `cd packages/react-native-quick-crypto && bun run test`. Bare `bun test` invokes Bun's test runner and is not this package's Jest script.
- C++ changes use formatting plus the relevant native/compiler checks, including `scripts/check-ncrypto-openssl-deprecations.sh` when ncrypto/OpenSSL compatibility is in scope.
- Native runtime behavior is tested in the example React Native app. Agents may build, install, drive, and test the app; user confirmation is not inherently required when current successful evidence is available.
- For targeted interactive debugging, attach to the existing RNQC app and Metro process first. Do not restart another project's process or take over its port. Metro client logs belong at `/tmp/rnqc-metro.log`; inspect them with `grep -E "FAIL|❌|failed" /tmp/rnqc-metro.log | tail -20` when diagnosing failures.
- For canonical full-app qualification, run `bun run e2e:ios` and then `bun run e2e:android` from the repository root. The runner owns its RNQC app, simulator or emulator, isolated Metro port, artifacts, and cleanup; do not substitute another project's app or an overlapping manually managed server.
- When the native merge gate applies, follow `docs/local-e2e.md`: use the trusted recipe, policy, and registry from `main` with the pinned patched AgentSCM producer; sign the exact clean committed HEAD, tree, base ref, and merge-base with owner-private key and state outside the checkout. Never fabricate an attestation from logs or raw test results and never post the status manually.
- Reuse still-current raw evidence during implementation and review, but the final delivery attestation must bind the final committed HEAD after plan moves, documentation commits, review fixes, and other changes. Its `agentscm/local-validation` context is worker-asserted evidence, not a claim that GitHub ran the mobile suites, and it is not currently a required branch-protection check unless live settings are separately verified.
- Pure documentation, plan, and `.agents/` changes do not require runtime retesting.
- Unverified runtime behavior that could change the diff blocks push/PR delivery unless the user explicitly directs shipment; disclose the unverified behavior and residual risk when they do.

## Real hooks and scripts

The tracked pre-commit hook runs `bun lint-staged`, a C++ `clang-format --dry-run --Werror` scan, `bun tsc`, and `bun --filter="react-native-quick-crypto" prepare`. Allow at least 120 seconds for `git commit` and fix hook failures rather than bypassing them.

Useful scripts and flows include:

- Root checks: `bun tsc`, `bun lint`, `bun format`.
- Node-side Jest: `cd packages/react-native-quick-crypto && bun run test`.
- Example app: `cd example && bun ios` or `bun android`.
- Explicit native builds: `cd example && bun run build:ios` or `bun run build:android`.
- Full app E2E when justified: from the repository root run `bun run e2e:ios` and then `bun run e2e:android`; the workspace wrappers invoke the Node runner. See `docs/local-e2e.md` for attested qualification and its coverage limits.

## Local references

- `$REPOS/node`: Node.js crypto and ncrypto reference.
- `$REPOS/ncrypto`: standalone OpenSSL abstraction and Node-derived utilities.
- `$REPOS/nitro`: Nitro bridging examples and iOS CI caching patterns.
- `$REPOS/spicy`: shared agent-workflow and Android E2E patterns only; do not import Spicy services, Jazz assumptions, golf domain rules, or scripts into RNQC.

## Quality checklist

- Type safety: no `any`; validate dynamic shapes.
- Memory safety: RAII, smart-pointer ownership, no leaks or invalid access.
- Cryptographic correctness: spec behavior, edge cases, and authoritative vectors.
- Security properties: constant-time comparisons, secure randomness, nonce discipline, and no secret leakage.
- Delivery evidence: checks match the actual diff and all claimed runtime behavior is verified or explicitly disclosed.
