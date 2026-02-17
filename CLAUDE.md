# React Native Quick Crypto - Claude Code Configuration

This project uses the **4-Layer Orchestra Architecture** for efficient multi-agent development.

## Quick Reference

- **Simple tasks (1-2 files)**: Work directly, no orchestration needed
- **Complex tasks (3+ files)**: Use the orchestrator agent
- **Rules**: See `.claude/rules/*.xml` for architectural constraints
- **Agents**: See `.claude/agents/*.md` for specialist definitions

## Critical Principles

### 1. API Priority Order (NON-NEGOTIABLE)
When implementing features, favor in this order:
1. **WebCrypto API** - Modern standard, best for `subtle.*` methods
2. **Node.js Implementation** - Use `$REPOS/node/deps/ncrypto` as reference
3. **ncrypto** - submodule code reference at `$REPOS/ncrypto` (do work w/ OpenSSL)

**Always check Node.js `deps/ncrypto` before implementing new features.**

### 2. Modern Stack Required
- **React Native** - Mobile framework
- **TypeScript** - Type system (strict mode, no `any`)
- **Nitro Modules** - Native bridging
- **C++20 or higher** - Modern C++ (smart pointers, RAII)
- **OpenSSL 3.6+** - Cryptographic library (EVP APIs only)
- **Bun 1.3+** - TypeScript package manager

### 3. Code Philosophy
- Minimize code rather than add more
- Prefer iteration and modularization over duplication
- No comments unless code is sufficiently complex
- Code should be self-documenting

### 4. Security is Critical
- Constant-time comparisons for authentication tags
- Cryptographically secure randomness (RAND_bytes)
- AEAD modes preferred (AES-GCM)
- No key material in errors/logs
- Validate against test vectors (NIST, RFC, Node.js)

## Rules Summary

For full details, see `.claude/rules/*.xml`:

### architecture.xml
- Project context and goals
- API priority order (WebCrypto → Node.js → ncrypto)
- Tech stack requirements
- Code philosophy
- Testing context (RN environment)
- Local codebase references

### code-typescript.xml
- No `any` or `unknown` casts
- Interfaces over types
- Named exports only (no default)
- No enums (use union types)
- Explicit return types
- Minimal, self-documenting code
- React best practices (minimal useEffect)

### code-cpp.xml
- C++20 minimum with modern features
- Smart pointers for all ownership
- OpenSSL 3.6+ EVP APIs only (no deprecated)
- RAII for all resources
- Proper error handling (ERR_get_error)
- Memory safety (no leaks, no raw ownership)

### crypto-security.xml
- Cryptographic correctness (match specs)
- No timing attacks (CRYPTO_memcmp)
- Secure RNG (RAND_bytes)
- Authenticated encryption (AEAD)
- Proper IV/nonce handling (never reuse)
- Minimum key sizes
- No key material in errors

### ci-caching.xml
- iOS Pods/DerivedData cache consistency (exact-match Pods, no restore-keys)
- Cache key design (no version suffixes, use hashFiles)
- Android Maestro patterns (don't launch app before Maestro)
- Reference implementations (Nitro for iOS, Spicy for Android)

## When to Use Orchestration

### Use Orchestrator For:
- ✅ Tasks touching 3+ files
- ✅ Cross-language changes (TypeScript + C++)
- ✅ New crypto features (API + implementation)
- ✅ Complex refactoring

### Work Directly For:
- ✅ Single file changes
- ✅ Simple bug fixes
- ✅ Type updates
- ✅ Documentation

## Available Specialists

- **orchestrator**: Decomposes complex tasks, coordinates specialists
- **typescript-specialist**: TypeScript API, types, Nitro bindings
- **cpp-specialist**: C++ implementation, OpenSSL integration
- **crypto-specialist**: Algorithm correctness, security review
- **testing-specialist**: Test strategy, test vectors, validation

## Local Codebase References

Use these instead of web searches:

- **Node.js**: `$REPOS/node`
  - `deps/ncrypto` - Use as bible for crypto operations
  - May need updating to OpenSSL 3.6+ patterns

- **ncrypto**: `$REPOS/ncrypto`
  - separate crypto lib broken out from Node.js
  - Patterns and tools to access OpenSSL

- **Nitro**: `$REPOS/nitro`
  - iOS CI caching patterns (super-fast builds)
  - Nitro Modules bridging examples

- **Spicy**: `$REPOS/spicy`
  - Android E2E patterns with Maestro
  - Separate build/test workflow

## Testing

Tests run in the React Native example app environment, not standard Node.js test runners. 

Don't ask to run tests - they must be executed in the example React Native application.

### Metro Logs

Metro output is tee'd to `/tmp/rnqc-metro.log`. When debugging test failures, read this file to see console output including test pass/fail results. Use `grep -E "FAIL|❌|failed" /tmp/rnqc-metro.log | tail -20` to quickly find failures.

## Quality Checks

Before committing:
- [ ] Type safety (no `any`, proper interfaces)
- [ ] Memory safety (smart pointers, RAII)
- [ ] Cryptographic correctness (test vectors)
- [ ] Security properties (constant-time, secure RNG)
- [ ] Code quality (minimal, modular, self-documenting)

---

**For specialist details and orchestration patterns, see `.claude/agents/*.md` and `.claude/rules/*.xml`**
