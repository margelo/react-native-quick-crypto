# Architecture Rules

Always on.

## Critical

- Project: React Native Quick Crypto provides native crypto for React Native.
- Bridge JS and C++ through Nitro Modules.
- Node.js `crypto` compatibility matters where this package exposes polyfills.
- API priority:
  1. WebCrypto API for `subtle.*`.
  2. Node.js `$REPOS/node/deps/ncrypto` for `crypto.*` polyfills.
  3. `$REPOS/ncrypto` as the standalone ncrypto reference.
- Before new crypto work, check Node.js `deps/ncrypto`; adapt to OpenSSL 3.6+ patterns.

## Strict

- Required stack: React Native, TypeScript, Nitro Modules, C++20+, OpenSSL 3.6+, Bun 1.3+.
- Use modern patterns. Avoid legacy APIs.
- Keep code minimal, modular, and self-documenting.
- Avoid comments unless the code is complex enough to need them.
- Tests run in the example React Native app, not a standard Node.js runner.

## References

- `$REPOS/node`: Node.js crypto/subtle reference.
- `$REPOS/ncrypto`: OpenSSL abstraction and Node-derived crypto utilities.
- `$REPOS/nitro`: Nitro bridging examples and iOS CI caching.
- `$REPOS/spicy`: Android E2E and Maestro workflow examples.
- Use local Nitro llms docs when available.

## Output

- When a rule materially affects a decision, mention the rule briefly.
