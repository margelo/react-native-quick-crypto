# Security Audit Plan

## Overview

A comprehensive security audit of every crypto module in `react-native-quick-crypto`. Each module gets reviewed by a team of specialist sub-agents running in parallel, scanning for vulnerabilities, bad practices, and correctness issues.

---

## Sub-Agent Definitions

### 1. Crypto Correctness Agent (`crypto-specialist`)

**Focus:** Algorithm implementation correctness and spec compliance.

- Verify implementations match relevant standards (NIST FIPS, RFCs, WebCrypto spec)
- Check for proper IV/nonce generation and uniqueness enforcement
- Validate key size constraints and parameter validation
- Confirm AEAD tag lengths and authenticated data handling
- Compare behavior against Node.js `deps/ncrypto` reference
- Verify post-quantum parameter sets (ML-DSA, ML-KEM) match FIPS 203/204
- Check KDF iteration counts and salt handling (PBKDF2, scrypt, Argon2, HKDF)

### 2. Memory Safety Agent (`cpp-specialist`)

**Focus:** C++ memory management, resource leaks, and undefined behavior.

- Audit all OpenSSL resource handling (EVP_CTX, BIO, BIGNUM, etc.) for proper cleanup
- Verify smart pointer usage — no raw `new`/`delete` or manual `free`
- Check for use-after-free, double-free, and dangling pointer risks
- Validate buffer bounds checking on all native data paths
- Review error paths for resource leaks (early returns, exceptions)
- Check for integer overflow in size calculations
- Verify all `Uint8Array` / `ArrayBuffer` access is bounds-checked

### 3. Side-Channel & Timing Agent (`crypto-specialist`)

**Focus:** Timing attacks, side channels, and key material exposure.

- Verify constant-time comparison (`CRYPTO_memcmp`) for all auth tag checks
- Check for branching on secret data (key bytes, plaintext)
- Audit error messages for key material leakage
- Verify `RAND_bytes` usage (not `rand()` or `Math.random()`)
- Check that key material is zeroed after use where possible
- Review logging/debug output for sensitive data exposure
- Validate `timingSafeEqual` implementation in TypeScript layer

### 4. TypeScript API Surface Agent (`typescript-specialist`)

**Focus:** Input validation, type safety, and API misuse prevention.

- Audit all public API entry points for input validation
- Check for `any` / `unknown` casts that bypass type safety
- Verify Buffer/Uint8Array conversions are safe (offset, length)
- Review error handling — do errors leak internal state?
- Check for prototype pollution vectors in option parsing
- Validate that TypeScript types match actual native behavior
- Review Nitro `.nitro.ts` specs for type mismatches with C++ implementations

### 5. Dependency & Supply Chain Agent (general-purpose)

**Focus:** NPM dependency vulnerabilities and supply chain risks.

- Run `npm audit` / `bun audit` on all workspace packages
- Check for known CVEs in direct and transitive dependencies
- Review `safe-buffer`, `readable-stream`, `events`, `string_decoder` for known issues
- Verify dependency pinning strategy (exact versions vs ranges)
- Check for typosquatting risks in dependency names
- Review `@craftzdog/react-native-buffer` for security patches
- Audit native deps (`blake3`, `ncrypto`, `fastpbkdf2`) for upstream vulnerabilities
- Check CocoaPods (`OpenSSL-Universal`) and Android native deps for known CVEs
- Verify no post-install scripts run arbitrary code
- Review lockfile integrity

### 6. Build & Distribution Agent (general-purpose)

**Focus:** Build pipeline security, CI/CD, and artifact integrity.

- Review GitHub Actions workflows for injection vulnerabilities
- Check for secrets exposure in CI logs
- Verify build reproducibility
- Review Expo plugin (`withRNQC`) for code injection risks
- Check that `.npmignore` / `files` field excludes test fixtures, keys, configs
- Verify no credentials or API keys in committed files

### 7. Test Coverage Agent (`testing-specialist`)

**Focus:** Identifying untested code paths, missing edge cases, and gaps in security-relevant test coverage.

- Compare each module's test suite against its implementation to find untested code paths
- Check for missing negative tests (invalid inputs, malformed data, wrong key sizes)
- Verify edge cases are covered: empty inputs, max-length inputs, zero-length keys
- Confirm error paths are tested (OpenSSL failures, allocation failures, invalid parameters)
- Check for missing cross-algorithm tests (e.g., encrypt with AES-GCM, decrypt with wrong mode)
- Verify test vectors from standards (NIST, RFC, Wycheproof) are used where available
- Identify modules with no tests at all
- Check that AEAD modules test: tag truncation, tag tampering, nonce reuse detection
- Verify KDFs test: minimum iteration/cost enforcement, salt length edge cases
- Check that key exchange modules test: invalid public keys, point-not-on-curve rejection
- Verify post-quantum modules have round-trip and known-answer tests
- Flag any tests that are skipped, commented out, or marked TODO

---

## Module Inventory & Progress

Each module is audited by all relevant agents. Status key:

- `[ ]` Not started
- `[~]` In progress
- `[x]` Complete
- `[!]` Issues found — see notes

### Hashing

| Module                         | Crypto | Memory | Timing | API | Tests | Notes                                           |
| ------------------------------ | ------ | ------ | ------ | --- | ----- | ----------------------------------------------- |
| Hash (SHA-1/256/384/512, SHA3) | [!]    | [!]    | [x]    | [!] | [!]   | 3H/3M crypto; 3H/3M/1L mem; 4M API; 4H/1M tests |
| HMAC                           | [!]    | [!]    | [!]    | [!] | [!]   | 1H/2M crypto; 2H/3M mem; 2H/4M API; 3H/5M tests |
| KMAC (128/256)                 | [x]    | [!]    | [x]    | [!] | [!]   | 0H/2M crypto; 2H/3M mem; 3H/5M API; 3H/4M tests |
| BLAKE3                         | [!]    | [!]    | [x]    | [!] | [!]   | 2M crypto; 2H/2M mem; 2H/3M API; 3H/4M tests    |

### Symmetric Encryption

| Module             | Crypto | Memory | Timing | API | Tests | Notes                                                            |
| ------------------ | ------ | ------ | ------ | --- | ----- | ---------------------------------------------------------------- |
| AES-CBC            | [!]    | [!]    | [x]    | [!] | [!]   | 2M crypto; 2H/2M mem; 0 timing; 4H API; 2H/2M/2L tests           |
| AES-CTR            | [!]    | [!]    | [x]    | [!] | [!]   | 2M crypto; 2H/2M mem; 0 timing; 4H API; 2H/1M/1L tests           |
| AES-GCM            | [!]    | [!]    | [x]    | [!] | [!]   | 2M/1L crypto; 1L mem; 0 timing; 4H/2M API; 3H/3M/1L tests        |
| AES-CCM            | [!]    | [!]    | [!]    | [!] | [!]   | 2H/3M crypto; 2H/1M mem; 1H/1M timing; 2H API; 3H/1M tests       |
| AES-OCB            | [!]    | [!]    | [x]    | [!] | [!]   | 2M/1L crypto; 1M mem; 0 timing; 1H/1M API; 2H/2M tests           |
| ChaCha20           | [x]    | [!]    | [!]    | [!] | [!]   | 1L crypto; 1H/1M mem; 1M timing; 1M/1L API; 2M/1L tests          |
| ChaCha20-Poly1305  | [!]    | [!]    | [!]    | [!] | [!]   | 1M/1L crypto; 1H/1M mem; 1M timing; 1H/1M API; 1H/3M tests       |
| XChaCha20-Poly1305 | [!]    | [!]    | [!]    | [!] | [x]   | 2M/1L crypto; 1M mem; 1H/2M timing; 1M API; 1M/1L tests          |
| XSalsa20           | [!]    | [!]    | [!]    | [!] | [!]   | 1H/2M crypto; 1M/1L mem; 1H timing; 1H/1M API; 2H/1M tests       |
| XSalsa20-Poly1305  | [x]    | [!]    | [!]    | [!] | [!]   | 1L crypto; 1M mem; 1M timing; 1M API; 1M/1L tests                |
| RSA Cipher         | [!]    | [!]    | [!]    | [!] | [!]   | 2M/1L crypto; 1H/1M mem; 1H/1M timing; 1H/3M API; 1H/3M/1L tests |

### Key Derivation

| Module          | Crypto | Memory | Timing | API | Tests | Notes                                      |
| --------------- | ------ | ------ | ------ | --- | ----- | ------------------------------------------ |
| PBKDF2          | [!]    | [!]    | [x]    | [!] | [!]   | 4H/2M/1L; fastpbkdf2 unchecked returns     |
| Scrypt          | [!]    | [!]    | [x]    | [!] | [!]   | 3H/3M/2L; N power-of-2 not validated       |
| HKDF            | [!]    | [!]    | [x]    | [!] | [!]   | 3H/4M/2L; RFC 5869 max not enforced        |
| Argon2 (d/i/id) | [!]    | [!]    | [x]    | [!] | [!]   | 3H/4M/2L; no param validation per RFC 9106 |

### Key Exchange

| Module         | Crypto | Memory | Timing | API | Tests | Notes                             |
| -------------- | ------ | ------ | ------ | --- | ----- | --------------------------------- |
| Diffie-Hellman | [!]    | [!]    | [!]    | [!] | [!]   | 4H/5M/3L; no peer key validation  |
| ECDH           | [!]    | [!]    | [!]    | [!] | [!]   | 3H/4M/3L; no point-on-curve check |

### Digital Signatures

| Module                | Crypto | Memory | Timing | API | Tests | Notes                                      |
| --------------------- | ------ | ------ | ------ | --- | ----- | ------------------------------------------ |
| Sign/Verify           | [!]    | [!]    | [!]    | [!] | [!]   | 3H/2M/2L; EVP_PKEY_CTX ownership confusion |
| ECDSA                 | [!]    | [!]    | [x]    | [!] | [!]   | 3H/2M/1L; no curve whitelist for Node API  |
| Ed25519/Ed448         | [!]    | [!]    | [!]    | [!] | [!]   | 3H/4M/1L; EVP_PKEY leak on import          |
| RSA (PKCS1-v1.5, PSS) | [!]    | [!]    | [x]    | [!] | [!]   | 1H/4M/1L; min modulus 256 bits             |
| DSA                   | [!]    | [x]    | [x]    | [!] | [!]   | 1H/2M/1L; no min modulus enforcement       |

### Post-Quantum

| Module                | Crypto | Memory | Timing | API | Tests | Notes                                  |
| --------------------- | ------ | ------ | ------ | --- | ----- | -------------------------------------- |
| ML-DSA (44/65/87)     | [!]    | [!]    | [x]    | [!] | [!]   | 2H/5M/3L; double-free risk in signSync |
| ML-KEM (512/768/1024) | [!]    | [!]    | [!]    | [!] | [!]   | 2H/5M/2L; shared secret not zeroed     |

### Key Management & Utilities

| Module              | Crypto | Memory | Timing | API | Tests | Notes                               |
| ------------------- | ------ | ------ | ------ | --- | ----- | ----------------------------------- |
| KeyObjectHandle     | [!]    | [!]    | [x]    | [!] | [!]   | 2H/3M/2L; 32-byte key misidentified |
| Random              | [x]    | [!]    | [x]    | [!] | [!]   | 1H/2M/2L; pow(2,31) fragile         |
| Prime               | [x]    | [x]    | [x]    | [!] | [!]   | 0H/2M/1L; no bit size validation    |
| Certificate / SPKAC | [x]    | [x]    | [x]    | [x] | [!]   | 0H/0M/2L; minimal surface           |
| X.509               | [x]    | [x]    | [x]    | [!] | [!]   | 0H/2M/2L; no null check on cert\_   |
| WebCrypto Subtle    | [!]    | N/A    | [!]    | [!] | [!]   | 5H/10M/5L; TS-only API surface      |
| Utils / Conversions | [!]    | [x]    | [!]    | [!] | [!]   | 1H/2M/1L; timingSafeEqual view bug  |

### Cross-Cutting

| Area                                           | Agent      | Status | Notes                           |
| ---------------------------------------------- | ---------- | ------ | ------------------------------- |
| NPM dependency audit                           | Dependency | [ ]    | All workspace packages          |
| Native dep audit (blake3, ncrypto, fastpbkdf2) | Dependency | [ ]    |                                 |
| CocoaPods / Android native deps                | Dependency | [ ]    | OpenSSL-Universal, libsodium    |
| CI/CD pipeline review                          | Build      | [ ]    | GitHub Actions                  |
| Package distribution review                    | Build      | [ ]    | .npmignore, published artifacts |
| Expo plugin review                             | Build      | [ ]    | withRNQC, sodium integration    |

---

## How to Run the Audit

Launch sub-agents in parallel, grouping by module category. Each agent receives:

1. The module's C++ files (from `packages/react-native-quick-crypto/cpp/<module>/`)
2. The module's TypeScript files (from `packages/react-native-quick-crypto/src/`)
3. The Nitro spec (from `src/specs/<module>.nitro.ts`)
4. Relevant test files (from `example/src/tests/`)
5. This checklist for tracking

**Example orchestration for a single module (e.g., AES-GCM):**

```
Launch in parallel:
  1. crypto-specialist     → Read cpp/cipher/GCMCipher.cpp, check correctness & timing
  2. cpp-specialist        → Read cpp/cipher/GCMCipher.cpp, check memory safety
  3. typescript-specialist → Read src/cipher.ts + src/specs/cipher.nitro.ts, check API surface
  4. testing-specialist    → Read example/src/tests/cipher/, compare against implementation, find gaps
```

**For cross-cutting audits:**

```
Launch in parallel:
  1. general-purpose (dependency) → Run npm audit, check CVEs, review lockfiles
  2. general-purpose (build)      → Review .github/workflows/, expo plugin, .npmignore
```

After each module completes, update the status in this table and note any findings.
Move this file to `plans/done/` when the full audit is complete.

---

## Recurring Patterns

Issues seen across multiple modules. These are systemic and should be addressed project-wide rather than per-module.

| Pattern                                             | Severity | Modules Affected                                 | Description                                                                                                                                                                                                               |
| --------------------------------------------------- | -------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Raw `new`/`delete` in digest                        | HIGH     | Hash, HMAC, KMAC, BLAKE3                         | Raw `new uint8_t[]` without RAII guard; leak window if `make_shared` or intervening code throws. Fix: `std::unique_ptr<uint8_t[]>` with `.release()` into `NativeArrayBuffer`.                                            |
| `double` → integer cast without validation          | HIGH     | Hash, HMAC, KMAC, BLAKE3                         | Length/size parameters arrive as `double` from JS. NaN, Infinity, negative values, and fractions are not validated before `static_cast<size_t>`. NaN/Infinity casts are UB in C++.                                        |
| `abvToArrayBuffer` ignores byte offset              | HIGH     | Hash, HMAC, KMAC, BLAKE3                         | Shared utility returns `.buffer` without respecting `byteOffset`/`byteLength`. Sliced typed arrays expose the entire backing buffer to native code. Not always on the hot path but exported and dangerous.                |
| No digest-once enforcement at TS layer              | MEDIUM   | Hash, HMAC, KMAC                                 | After `digest()` is called, subsequent `update()`/`digest()` calls should throw. TS layer relies entirely on native to enforce this, producing cryptic errors. BLAKE3 is exempt (non-destructive finalize).               |
| Key material retained in TS after native handoff    | MEDIUM   | HMAC, BLAKE3                                     | Key stored as instance property after being passed to native. Never read again, never cleared. Increases exposure window via heap dumps/debuggers.                                                                        |
| OpenSSL error queue not cleared                     | LOW      | Hash, HMAC, KMAC                                 | `ERR_get_error()` pops one error but doesn't clear the queue. Stale errors can pollute subsequent operations.                                                                                                             |
| Unsafe `as Encoding` cast in `_transform`           | MEDIUM   | Hash, HMAC                                       | Stream `_transform` casts `BufferEncoding` → `Encoding` without validation. Unsupported encodings silently misbehave.                                                                                                     |
| Stream `_transform`/`_flush` don't propagate errors | MEDIUM   | Hash, HMAC                                       | Errors thrown in `update()` crash the process instead of propagating via the stream callback.                                                                                                                             |
| Test suites lack standard test vectors              | HIGH     | Hash, BLAKE3                                     | Hash has no NIST vectors; BLAKE3 has no official keyed_hash/derive_key vectors. Some modes would pass tests even with broken implementations.                                                                             |
| Subclass destructor leaks EVP_CIPHER_CTX            | HIGH     | CCMCipher, ChaCha20, ChaCha20-Poly1305           | Destructors set `ctx = nullptr` before parent `~HybridCipher()` runs. Parent sees null and skips `EVP_CIPHER_CTX_free`. Fix: convert `ctx` to `unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>` in base class. |
| `setAAD` ignores Buffer byte offsets                | HIGH     | AES-GCM, AES-CCM, AES-OCB, ChaCha20-Poly1305     | `setAAD` passes `buffer.buffer` (entire backing ArrayBuffer) ignoring `byteOffset`/`byteLength`. Sliced Buffers send wrong AAD data — direct AEAD integrity violation.                                                    |
| No TS-boundary input validation for ciphers         | MEDIUM   | All symmetric ciphers                            | Algorithm name, key length, and IV length are not validated at the TypeScript layer. Invalid inputs produce opaque native errors. Node.js validates these early.                                                          |
| Stream `_transform`/`_flush` don't propagate errors | MEDIUM   | Hash, HMAC, All Ciphers                          | Errors thrown in `update()`/`final()` crash the process instead of propagating via the stream callback. AEAD auth failures in `_flush` are especially dangerous.                                                          |
| `std::memset` for key zeroing may be optimized away | MEDIUM   | XChaCha20-Poly1305, XSalsa20-Poly1305            | Non-sodium destructor paths use `std::memset` which compilers may optimize away. Use `OPENSSL_cleanse` or `sodium_memzero` instead.                                                                                       |
| Key material never zeroed in destructor             | HIGH     | XSalsa20                                         | `key[32]` and `nonce[24]` arrays persist in freed heap memory. Other libsodium ciphers at least attempt zeroing.                                                                                                          |
| RSA error messages enable padding oracles           | HIGH     | RSA Cipher                                       | Error messages propagate OpenSSL internal strings; `publicDecrypt` has distinguishable error paths (empty buffer vs exception). Combined with PKCS#1 v1.5 support, this risks Bleichenbacher attacks.                     |
| Prototype pollution in key preparation              | HIGH     | RSA Cipher                                       | `'key' in key` traverses prototype chain in `preparePublicCipherKey`/`preparePrivateCipherKey`. Polluted `Object.prototype.key` triggers wrong code path.                                                                 |
| Unbounded data accumulation in libsodium ciphers    | MEDIUM   | XChaCha20-Poly1305, XSalsa20-Poly1305            | One-shot libsodium API requires buffering all data in `update()`. No size limit; potential OOM and `size_t` overflow on 32-bit platforms.                                                                                 |
| No NIST/RFC test vectors for AEAD ciphers           | HIGH     | AES-GCM, AES-CCM, AES-OCB                        | All AEAD modes only use round-trip tests. No authoritative known-answer verification. Consistently-wrong encrypt/decrypt would pass.                                                                                      |
| Zero dedicated tests for CCM and OCB                | HIGH     | AES-CCM, AES-OCB                                 | Most complex AEAD implementations have no targeted test coverage — only generic round-trip loop.                                                                                                                          |
| No AEAD API misuse tests                            | HIGH     | AES-GCM, AES-CCM, AES-OCB, ChaCha20-Poly1305     | No tests for: setAAD after update, getAuthTag on decipher, setAuthTag on cipher, missing setAuthTag before decrypt. Common developer mistakes untested.                                                                   |
| No wrong key/IV size rejection tests                | HIGH     | All symmetric ciphers                            | No test verifies that invalid key or IV sizes are properly rejected through the JS layer.                                                                                                                                 |
| Derived key material never zeroed                   | MEDIUM   | PBKDF2, Scrypt, HKDF, Argon2                     | Derived key buffers `delete[]`'d without `OPENSSL_cleanse`. Key material persists in freed heap memory.                                                                                                                   |
| `double` → integer cast without validation (KDFs)   | HIGH     | PBKDF2, Scrypt, HKDF, Argon2                     | All numeric parameters cross JS-to-C++ bridge as `double` and are `static_cast`'d without checking NaN, Infinity, negative, or out-of-range at C++ layer.                                                                 |
| Raw `new uint8_t[]` allocation (KDFs)               | MEDIUM   | PBKDF2, Scrypt, HKDF                             | Output buffers allocated with raw `new`; exception between alloc and `make_shared` leaks. Should use `std::unique_ptr<uint8_t[]>` with release-on-success.                                                                |
| Insufficient TS-layer validation (KDFs)             | HIGH     | Scrypt, HKDF, Argon2                             | Scrypt: N power-of-2 unchecked. HKDF: max output length unchecked. Argon2: no param ranges validated. PBKDF2 is only KDF with thorough TS validation.                                                                     |
| Missing RFC test vectors (KDFs)                     | HIGH     | HKDF, Argon2                                     | HKDF: 1 of 7 RFC 5869 vectors. Argon2: RFC 9106 vector output not compared against expected value.                                                                                                                        |
| `keylen=0` handling inconsistent                    | MEDIUM   | PBKDF2, Scrypt, HKDF                             | TS layers allow `keylen >= 0` but C++ behavior varies: PBKDF2 does `new uint8_t[0]`, Scrypt/HKDF throw. None tested.                                                                                                      |
| Missing peer public key validation                  | HIGH     | DH, ECDH                                         | DH: no range check [2, p-2]. ECDH: no point-on-curve validation. Single most critical key exchange gap.                                                                                                                   |
| Secret material not zeroed (key exchange)           | HIGH     | DH, ECDH                                         | Shared secrets in `std::vector<uint8_t>` not securely erased with `OPENSSL_cleanse` before destruction.                                                                                                                   |
| Deprecated DH API usage                             | MEDIUM   | DH                                               | Uses deprecated `DH_*` APIs (DH_new, DH_generate_key, DH_set0_pqg) deprecated in OpenSSL 3.x. ECDH correctly uses modern EVP/OSSL_PARAM.                                                                                  |
| Inconsistent minimum key size enforcement           | MEDIUM   | DH, RSA, DSA                                     | DH: `initWithSize` enforces 2048-bit but `init`/`DhKeyPair` don't. RSA: minimum 256 bits. DSA: minimum 0 bits.                                                                                                            |
| Raw `EVP_PKEY*` without smart pointers              | MEDIUM   | RSA KeyPair, EC KeyPair, Ed KeyPair, Sign/Verify | Raw pointer with manual `EVP_PKEY_free` in destructor. DSA is the only module using `unique_ptr`. Violates C++20 mandate.                                                                                                 |
| Private key DER in `std::string` not zeroed         | MEDIUM   | RSA, EC, DSA, Ed25519                            | All modules copy private key DER bytes into `std::string` that is not zeroed before destruction.                                                                                                                          |
| EVP_PKEY_CTX ownership confusion in DigestSignInit  | HIGH     | Sign/Verify, Ed25519, ML-DSA                     | Pre-created `EVP_PKEY_CTX` passed to `EVP_DigestSignInit`; ownership after partial failure is ambiguous, risking double-free.                                                                                             |
| Thread-unsafe `ERR_error_string`                    | HIGH     | Ed25519                                          | `ERR_error_string(ERR_get_error(), NULL)` uses static internal buffer. Other modules correctly use `ERR_error_string_n`.                                                                                                  |
| No key-type validation at C++ layer (signing)       | HIGH     | Sign/Verify                                      | C++ `sign()`/`verify()` accept any key type. Validation only in TypeScript, bypassable via Nitro bridge.                                                                                                                  |
| Self-signing tests only (signatures)                | MEDIUM   | All signature modules                            | Every test generates keys and verifies own signatures. No standard test vectors; systematic algorithm errors undetectable.                                                                                                |
| No RAII for OpenSSL contexts (PQ)                   | MEDIUM   | ML-DSA, ML-KEM                                   | `EVP_MD_CTX`, `EVP_PKEY_CTX`, BIO objects managed with manual `free` on each error path.                                                                                                                                  |
| Raw `this` in async lambdas                         | MEDIUM   | ML-DSA, ML-KEM, DH                               | `Promise::async` captures `this` by raw pointer. Object destruction during async execution = use-after-free.                                                                                                              |
| `#if !HAS_*` without `#else`                        | MEDIUM   | ML-DSA, ML-KEM                                   | `setVariant` throws on old OpenSSL but falls through to execute unreachable code.                                                                                                                                         |
| Missing NIST KAT vectors (PQ)                       | MEDIUM   | ML-DSA, ML-KEM                                   | All tests are round-trip only. No KAT vectors from FIPS 203/204.                                                                                                                                                          |
| Deprecated RSA API in KeyObjectHandle               | MEDIUM   | KeyObjectHandle                                  | JWK import/export uses `RSA_new()`, `RSA_set0_key()`, `EVP_PKEY_assign_RSA()` — deprecated in OpenSSL 3.x.                                                                                                                |
| WebCrypto spec non-compliance                       | HIGH     | Subtle                                           | Algorithm names not case-insensitive. JWK `ext`/`key_ops` not validated. HKDF extractable not enforced. `deriveBits` accepts `deriveKey` usage.                                                                           |
| `as unknown as` type casts                          | MEDIUM   | Subtle                                           | Multiple `as unknown as SomeType` casts bypass TypeScript type safety with no runtime validation.                                                                                                                         |

---

## Findings Log

_Record issues here as they are discovered. Format: `[severity] module — description`_

### Hash (SHA-1/256/384/512, SHA3)

**HIGH:**

- [HIGH] Hash — `size_t digestSize` compared `< 0` is always false; negative `outputLength` wraps to massive allocation (HybridHash.cpp:98-101)
- [HIGH] Hash — `reinterpret_cast<unsigned int*>(&hashLength)` aliasing violation; `size_t` is 8 bytes but OpenSSL writes 4 (HybridHash.cpp:111)
- [HIGH] Hash — Raw `new uint8_t[]` without RAII guard; leak window on future code changes (HybridHash.cpp:105)
- [HIGH] Hash — `abvToArrayBuffer` ignores `byteOffset`/`byteLength` on typed array views (utils/conversion.ts:17-25, shared utility)
- [HIGH] Hash — No NIST/RFC standard test vectors for any hash algorithm
- [HIGH] Hash — No double-`digest()` call test (use-after-free prevention path untested)
- [HIGH] Hash — Many algorithms untested via `createHash`: SHA-224, SHA-384, BLAKE2B-512, RIPEMD-160, SHA3-224, etc.
- [HIGH] Hash — `asyncDigest` error paths completely untested (invalid algo, cSHAKE missing length, length % 8)

**MEDIUM:**

- [MEDIUM] Hash — `setParams()` deferred to `digest()` instead of `createHash()`; fails late vs Node.js behavior (HybridHash.cpp:94)
- [MEDIUM] Hash — `double` to `uint32_t` truncation for XOF length; NaN/Infinity/fractions pass through (HybridHash.cpp:164)
- [MEDIUM] Hash — Raw pointer members `ctx`/`md` should use `unique_ptr` with custom deleters (HybridHash.hpp:36-37)
- [MEDIUM] Hash — `copy()` shares `md` pointer; dangling if original destroyed first (HybridHash.cpp:141)
- [MEDIUM] Hash — No null check on `buffer->data()` in `update()` (HybridHash.cpp:83)
- [MEDIUM] Hash — `outputLength` validation order: range check before type check, NaN/Infinity pass (hash.ts:51-63)
- [MEDIUM] Hash — `_transform` casts `BufferEncoding` to `Encoding` unsafely (hash.ts:187-194)
- [MEDIUM] Hash — `asyncDigest` doesn't validate `algorithm.name` is a string at runtime (hash.ts:239)
- [MEDIUM] Hash — No `copy()` after `digest()` test, no encoding variant tests, no large input tests

**LOW:**

- [LOW] Hash — cSHAKE bits/bytes ambiguity in length parameter (hash.ts:259-273)
- [LOW] Hash — No guard against calling `digest()` twice at TS or C++ layer
- [LOW] Hash — `hashnames.ts` uses `enum` violating project rules
- [LOW] Hash — No unicode hashing tests, no concurrent hash tests, no `outputLength` on non-XOF test

### HMAC

**HIGH:**

- [HIGH] HMAC — No constant-time HMAC verification API; users must manually use `timingSafeEqual` (design gap, matches Node.js)
- [HIGH] HMAC — Raw pointer `EVP_MAC_CTX*` enables double-free on copy, leak on re-init (HybridHmac.hpp:28)
- [HIGH] HMAC — `createHmac()` error path leaves `ctx` allocated but uninitialized; subsequent `update()` = UB (HybridHmac.cpp:36-40)
- [HIGH] HMAC — Key material stored on TS instance after native handoff; never cleared (hmac.ts:17,37)
- [HIGH] HMAC — `abvToArrayBuffer` leaks entire backing buffer (shared utility, not on HMAC path but risky)
- [HIGH] HMAC — `digest()` does not invalidate context; double-`digest()` and `update()`-after-`digest()` = UB (HybridHmac.cpp)
- [HIGH] HMAC — No test for double-`digest()`, `update()`-after-`digest()`, or HMAC verification workflow

**MEDIUM:**

- [MEDIUM] HMAC — Empty key handling substitutes `0x00` byte; diverges from spec intent (HybridHmac.cpp:50-55)
- [MEDIUM] HMAC — No digest-once enforcement at TS or C++ layer
- [MEDIUM] HMAC — Raw `new`/`delete` in `digest()` without RAII guard (HybridHmac.cpp:93)
- [MEDIUM] HMAC — `EVP_MD_get_size` return unchecked; -1 wraps to massive `size_t` (HybridHmac.cpp:90)
- [MEDIUM] HMAC — No null check on `ArrayBuffer::data()` in key or update paths (HybridHmac.cpp:47,76)
- [MEDIUM] HMAC — No TS-side guard against double `digest()` (hmac.ts:78-86)
- [MEDIUM] HMAC — Unsafe `as Encoding` cast in `_transform` (hmac.ts:94)
- [MEDIUM] HMAC — No algorithm normalization or validation against known set (hmac.ts:20-22)
- [MEDIUM] HMAC — Stream `_transform`/`_flush` don't propagate errors via callback (hmac.ts:89-99)
- [MEDIUM] HMAC — No tests for SHA3 algorithms, empty `update()`, large data, or `undefined` key

**LOW:**

- [LOW] HMAC — `EVP_MAC*` not wrapped in RAII for `createHmac()` scope (HybridHmac.cpp:30-31)
- [LOW] HMAC — OpenSSL error queue not cleared after `ERR_get_error()` calls
- [LOW] HMAC — Dead `algorithm` property stored on TS instance (hmac.ts:16)
- [LOW] HMAC — No prototype pollution guard on `options` passthrough to Transform (hmac.ts:31)

### KMAC (128/256)

**HIGH:**

- [HIGH] KMAC — `abvToArrayBuffer` loses byte offset on sliced views; affects `timingSafeEqual` path in verify (utils/conversion.ts:17-25)
- [HIGH] KMAC — No upper bound on `outputLengthBits`; unbounded allocation in C++ (subtle.ts:752-762, HybridKmac.cpp:71)
- [HIGH] KMAC — Negative `algorithm.length` bypasses zero-length key check in `kmacGenerateKey` (subtle.ts:724-734)
- [HIGH] KMAC — `double` to `size_t` cast without NaN/negative/overflow validation (HybridKmac.cpp:15)
- [HIGH] KMAC — Raw `new uint8_t[]` without RAII guard in `digest()` (HybridKmac.cpp:71)
- [HIGH] KMAC — No KMACXOF (extensible output) tests or documentation of exclusion
- [HIGH] KMAC — Algorithm name passed directly to OpenSSL without C++ validation; no error tests
- [HIGH] KMAC — Empty data input not tested; no NIST vector for 0-byte message

**MEDIUM:**

- [MEDIUM] KMAC — Timing leak on signature length mismatch (acceptable, matches Node.js) (subtle.ts:787-789)
- [MEDIUM] KMAC — Raw `new`/`delete` pattern in `digest()` (HybridKmac.cpp:71-80)
- [MEDIUM] KMAC — No null check on `customization` shared_ptr value (HybridKmac.cpp:36)
- [MEDIUM] KMAC — No null check on `key` or `data` shared_ptrs (HybridKmac.cpp:44,61)
- [MEDIUM] KMAC — `exportKeyJWK` return type is `unknown`; cast bypasses type safety (subtle.ts:1477)
- [MEDIUM] KMAC — Unsafe `as JWK` / `as BinaryLike` casts in `kmacImportKey` without validation (subtle.ts:813,841)
- [MEDIUM] KMAC — Streaming interface allows `update` after `digest` without TS guard (specs/kmac.nitro.ts)
- [MEDIUM] KMAC — Zero negative/error tests (8 error paths untested)
- [MEDIUM] KMAC — No tests for non-default output lengths
- [MEDIUM] KMAC — No tests for `generateKey` with custom length or empty vs absent customization

**LOW:**

- [LOW] KMAC — No minimum key length enforcement per NIST SP 800-185 (HybridKmac.cpp:47)
- [LOW] KMAC — No `EVP_MAC_final` output length verification (HybridKmac.cpp:73)
- [LOW] KMAC — Single-use digest not documented in TS interface
- [LOW] KMAC — OpenSSL error queue not cleared after `ERR_get_error()` calls
- [LOW] KMAC — No tests for multiple `update()` calls, key size boundaries, or additional NIST vectors

### BLAKE3

**HIGH:**

- [HIGH] BLAKE3 — Raw `new uint8_t[]` in `digest()` leaks on `make_shared` failure (HybridBlake3.cpp:70)
- [HIGH] BLAKE3 — NaN/Infinity pass length validation; `static_cast<size_t>(NaN)` is UB (HybridBlake3.cpp:67)
- [HIGH] BLAKE3 — Key material retained in TS `keyData` field after native handoff (blake3.ts:21,38)
- [HIGH] BLAKE3 — `abvToArrayBuffer` byte offset bug (recurring, not on BLAKE3 path but exported)
- [HIGH] BLAKE3 — No official test vectors used for keyed_hash or derive_key modes — zero correctness verification
- [HIGH] BLAKE3 — XOF extended output never verified against known values
- [HIGH] BLAKE3 — keyed_hash mode would pass all tests even with broken implementation

**MEDIUM:**

- [MEDIUM] BLAKE3 — Key material not securely erased on destruction; `hasher.key` and stored `key` persist (HybridBlake3.hpp:15)
- [MEDIUM] BLAKE3 — `reset()` silently does nothing if key/context optional is empty (HybridBlake3.cpp:85-94)
- [MEDIUM] BLAKE3 — `memcpy` on `blake3_hasher` struct in `copy()` without `is_trivially_copyable` guard (HybridBlake3.cpp:105)
- [MEDIUM] BLAKE3 — No TS-side validation on digest length parameter (blake3.ts:61-82)
- [MEDIUM] BLAKE3 — `copy()` creates and discards throwaway native object (blake3.ts:90)
- [MEDIUM] BLAKE3 — `key` option typed as `Uint8Array` only, not `BinaryLike` (blake3.ts:13)
- [MEDIUM] BLAKE3 — Output length boundary conditions untested (0, 1, 65535, >65535, negative, fractional)
- [MEDIUM] BLAKE3 — Double-digest, empty-data update, and derive_key reset untested

**LOW:**

- [LOW] BLAKE3 — XOF output capped at 65535 bytes; arbitrary undocumented limit (HybridBlake3.cpp:64)
- [LOW] BLAKE3 — Stack-local `keyArray` in `initKeyed()` not zeroed after use (HybridBlake3.cpp:24)
- [LOW] BLAKE3 — `getVersion()` not verified against expected "1.8.2" constant
- [LOW] BLAKE3 — Large input test has no correctness verification (only checks length)

### AES-CBC

**HIGH:**

- [HIGH] AES-CBC — `auth_tag_state` uninitialized in HybridCipher constructor; UB if checked before `setArgs()` (HybridCipher.hpp:62)
- [HIGH] AES-CBC — Integer overflow in `update()`: `in_len + EVP_CIPHER_CTX_block_size(ctx)` overflows `int` near INT_MAX (HybridCipher.cpp:116)
- [HIGH] AES-CBC — `setAAD` passes `buffer.buffer` ignoring `byteOffset`/`byteLength`; sliced Buffer sends wrong AAD (cipher.ts:204-219)
- [HIGH] AES-CBC — Stream `_transform`/`_flush` don't propagate errors via callback; native errors crash process (cipher.ts:182-194)

**MEDIUM:**

- [MEDIUM] AES-CBC — No algorithm name validation at TS boundary; invalid names pass to native (cipher.ts:81-123)
- [MEDIUM] AES-CBC — No key length validation; wrong key size produces opaque native error (cipher.ts:81-123)
- [MEDIUM] AES-CBC — No IV length validation; AES-CBC requires 16-byte IV (cipher.ts:81-123)
- [MEDIUM] AES-CBC — `update()` uses raw `new`/`delete`; leak window between alloc and `make_shared` (HybridCipher.cpp:117)
- [MEDIUM] AES-CBC — Intermediate key buffer from JS bridge never zeroed after EVP_CipherInit_ex (HybridCipher.cpp)

**LOW:**

- [LOW] AES-CBC — `max_message_size` member uninitialized and unused (HybridCipher.hpp:64)
- [LOW] AES-CBC — OpenSSL error queue not cleared after `ERR_get_error()` calls (HybridCipher.cpp)
- [LOW] AES-CBC — `setAutoPadding` exposed but no TS-side guidance for block-alignment requirement (cipher.ts:196-202)

### AES-CTR

**HIGH:**

- [HIGH] AES-CTR — Same `auth_tag_state` uninitialized UB as AES-CBC (HybridCipher.hpp:62)
- [HIGH] AES-CTR — Same integer overflow in `update()` as AES-CBC (HybridCipher.cpp:116)
- [HIGH] AES-CTR — Same `setAAD` buffer offset bug as AES-CBC (cipher.ts:204-219)
- [HIGH] AES-CTR — Same stream error propagation bug as AES-CBC (cipher.ts:182-194)

**MEDIUM:**

- [MEDIUM] AES-CTR — No algorithm/key/IV validation at TS boundary; AES-CTR requires 16-byte IV (cipher.ts:81-123)
- [MEDIUM] AES-CTR — Same raw `new`/`delete` in `update()` as AES-CBC (HybridCipher.cpp:117)

**LOW:**

- [LOW] AES-CTR — `setAutoPadding` exposed but meaningless for stream cipher (cipher.ts:196-202)

### AES-GCM

**HIGH:**

- [HIGH] AES-GCM — `setAAD` passes `buffer.buffer` ignoring byte offsets; wrong AAD = AEAD integrity violation (cipher.ts:204-219)
- [HIGH] AES-GCM — `getAuthTag()` callable before `final()` and on decipher instances; may return garbage (cipher.ts:221-223)
- [HIGH] AES-GCM — `authTagLength` options parsing uses `Record<string, any>` defeating type safety; prototype chain leak (utils/cipher.ts:52)
- [HIGH] AES-GCM — Same stream error propagation bug; GCM auth failure in `_flush` crashes process (cipher.ts:182-194)

**MEDIUM:**

- [MEDIUM] AES-GCM — `getAuthTag()` always retrieves 16 bytes from OpenSSL regardless of requested `auth_tag_len` (HybridCipher.cpp:246-260)
- [MEDIUM] AES-GCM — No key size validation (must be 16/24/32) at C++ or TS layer (GCMCipher.cpp)
- [MEDIUM] AES-GCM — No auth tag length validation; GCM allows {4,8,12,13,14,15,16} only (cipher.ts:225-231)
- [MEDIUM] AES-GCM — NIST recommends 12-byte IV; no warning for non-standard IV lengths (cipher.ts)
- [MEDIUM] AES-GCM — `auth_tag_state` uninitialized (inherited from base class)

**LOW:**

- [LOW] AES-GCM — Allows zero-length IV; cryptographically disastrous (GCMCipher.cpp:40)

### AES-CCM

**HIGH:**

- [HIGH] AES-CCM — Double key/IV initialization: base `init()` sets key+IV before CCM tag/IV lengths configured (CCMCipher.cpp:9-52)
- [HIGH] AES-CCM — Destructor sets `ctx = nullptr` before parent runs; leaks EVP_CIPHER_CTX every time (CCMCipher.hpp:10-13)
- [HIGH] AES-CCM — `authTagLength` silently defaults to 16 when using general `string` overload; CCM requires explicit tag length (cipher.ts:277-306)
- [HIGH] AES-CCM — `setAAD` does not enforce required `plaintextLength` for CCM; Node.js throws ERR_CRYPTO_INVALID_MESSAGELEN (cipher.ts:204-219)

**MEDIUM:**

- [MEDIUM] AES-CCM — `setAAD` skips total plaintext length on decrypt when AAD empty; CCM always requires it (CCMCipher.cpp:180-188)
- [MEDIUM] AES-CCM — `double` to `int` truncation in `setAAD` without NaN/Infinity validation (CCMCipher.cpp:158)
- [MEDIUM] AES-CCM — Tag length validation allows odd values; NIST SP 800-38C requires {4,6,8,10,12,14,16} (HybridCipher.cpp:220-221)
- [MEDIUM] AES-CCM — `kMaxMessageSize` hardcoded for 12-byte nonce only; wrong for other nonce lengths (CCMCipher.hpp:23)
- [MEDIUM] AES-CCM — Tautological `in_len < 0` comparison; `size_t` is unsigned (CCMCipher.cpp:60)
- [MEDIUM] AES-CCM — `setAuthTag` not enforced before decrypt `update()`; decryption without auth proceeds (CCMCipher.cpp:66)

### AES-OCB

**HIGH:**

- [HIGH] AES-OCB — `authTagLength` silently defaults when using general `string` overload; OCB requires explicit tag (cipher.ts:315-319)

**MEDIUM:**

- [MEDIUM] AES-OCB — `auth_tag_len` member shadows base class member; inconsistent state between `setArgs()` and OCB methods (OCBCipher.hpp:16)
- [MEDIUM] AES-OCB — `init()` signature hides (not overrides) base class virtual `init()`; polymorphic calls use wrong method (OCBCipher.hpp:10)
- [MEDIUM] AES-OCB — Same `setAAD` buffer offset bug as AES-GCM; integrity violation for AEAD (cipher.ts:204-219)

**LOW:**

- [LOW] AES-OCB — Tag length minimum 8 is more restrictive than RFC 7253 (allows 1-16); diverges from Node.js (OCBCipher.cpp:17)

### ChaCha20

**HIGH:**

- [HIGH] ChaCha20 — Destructor sets `ctx = nullptr` before parent runs; leaks EVP_CIPHER_CTX (ChaCha20Cipher.hpp:10-13)

**MEDIUM:**

- [MEDIUM] ChaCha20 — Key/IV validation after context allocation; failed validation leaks `ctx` (ChaCha20Cipher.cpp:43-50)
- [MEDIUM] ChaCha20 — Destructor leaks EVP context retaining key material in freed heap memory (ChaCha20Cipher.hpp:19-22)
- [MEDIUM] ChaCha20 — No IV length validation at TS boundary; requires 16-byte IV (cipher.ts:81-123)

**LOW:**

- [LOW] ChaCha20 — `final()` skips `EVP_CipherFinal_ex`; OpenSSL state never properly closed (ChaCha20Cipher.cpp:91)
- [LOW] ChaCha20 — No authentication; by design but callers must be aware

### ChaCha20-Poly1305

**HIGH:**

- [HIGH] ChaCha20-Poly1305 — Destructor sets `ctx = nullptr` before parent runs; leaks EVP_CIPHER_CTX (ChaCha20Poly1305Cipher.hpp:10-13)
- [HIGH] ChaCha20-Poly1305 — Same `setAAD` buffer offset bug; wrong AAD breaks AEAD authentication (cipher.ts:204-219)

**MEDIUM:**

- [MEDIUM] ChaCha20-Poly1305 — `final()` writes to zero-length `new unsigned char[0]` buffer; UB if EVP writes any bytes (ChaCha20Poly1305Cipher.cpp:98-100)
- [MEDIUM] ChaCha20-Poly1305 — Auth tag must be exactly 16 bytes; no TS-side length validation (cipher.ts:225-231)
- [MEDIUM] ChaCha20-Poly1305 — IV must be exactly 12 bytes; no TS-side validation (cipher.ts:81-123)
- [MEDIUM] ChaCha20-Poly1305 — Destructor leaks EVP context retaining key material (ChaCha20Poly1305Cipher.hpp)

**LOW:**

- [LOW] ChaCha20-Poly1305 — No AAD-before-update ordering enforcement (ChaCha20Poly1305Cipher.cpp)

### XChaCha20-Poly1305

**HIGH:**

- [HIGH] XChaCha20-Poly1305 — Non-sodium destructor `std::memset` may be optimized away; key material persists (XChaCha20Poly1305Cipher.cpp:22-26)

**MEDIUM:**

- [MEDIUM] XChaCha20-Poly1305 — Unbounded data accumulation in `update()` via `data_buffer_.resize()`; OOM + potential `size_t` overflow on 32-bit (XChaCha20Poly1305Cipher.cpp:59-61)
- [MEDIUM] XChaCha20-Poly1305 — Non-sodium path does not zero `data_buffer_` or `aad_` vectors in destructor (XChaCha20Poly1305Cipher.cpp:27-28)
- [MEDIUM] XChaCha20-Poly1305 — `update()` returns null/empty buffer; streaming interface misleading — all processing in `final()` (XChaCha20Poly1305Cipher.cpp:51-64)
- [MEDIUM] XChaCha20-Poly1305 — No TS-layer guidance that algorithm not in OpenSSL; depends on C++ fallback (cipher.ts)

**LOW:**

- [LOW] XChaCha20-Poly1305 — Preprocessor `#ifdef` vs `#if` inconsistency with XSalsa20Cipher.hpp (XChaCha20Poly1305Cipher.hpp:3)
- [LOW] XChaCha20-Poly1305 — Entire message buffered for one-shot libsodium API; large payload DoS risk

### XSalsa20

**HIGH:**

- [HIGH] XSalsa20 — **CATASTROPHIC**: `crypto_stream_xor` restarts keystream from counter=0 on each `update()` call; identical keystream XORed with different plaintext blocks (XSalsa20Cipher.cpp:44)
- [HIGH] XSalsa20 — Key material (`key[32]`, `nonce[24]`) never zeroed in destructor (XSalsa20Cipher.hpp:19-22)
- [HIGH] XSalsa20 — Zero input validation in TS layer: key size, nonce size, empty data all unchecked (cipher.ts:352-373)

**MEDIUM:**

- [MEDIUM] XSalsa20 — Key/nonce validation uses `<` instead of `!=`; accepts oversized keys silently (XSalsa20Cipher.cpp:18,24)
- [MEDIUM] XSalsa20 — `output` and `counter` parameters silently ignored with `@ts-expect-error` (cipher.ts:356-361)

**LOW:**

- [LOW] XSalsa20 — `update()` leaks `output` buffer on `crypto_stream_xor` failure (XSalsa20Cipher.cpp:43-47)
- [LOW] XSalsa20 — No authentication; by design but callers must be aware

### XSalsa20-Poly1305

**MEDIUM:**

- [MEDIUM] XSalsa20-Poly1305 — Non-sodium destructor `std::memset` may be optimized away (XSalsa20Poly1305Cipher.cpp:20-22)
- [MEDIUM] XSalsa20-Poly1305 — Unbounded data accumulation in `update()` with no size limit (XSalsa20Poly1305Cipher.cpp:54-56)
- [MEDIUM] XSalsa20-Poly1305 — No dedicated TS API; behavior through generic `createCipheriv` undefined (cipher.ts)

**LOW:**

- [LOW] XSalsa20-Poly1305 — AAD not supported; `setAAD` throws explicit error (correct behavior) (XSalsa20Poly1305Cipher.cpp:104-106)
- [LOW] XSalsa20-Poly1305 — Same buffering design as XChaCha20-Poly1305; large payload concern

### RSA Cipher

**HIGH:**

- [HIGH] RSA Cipher — Raw `EVP_PKEY_CTX*` without RAII; `toOpenSSLPadding()` throw leaks context in 5 methods (HybridRsaCipher.cpp)
- [HIGH] RSA Cipher — RSA PKCS#1 v1.5 padding for decryption enables Bleichenbacher padding oracle; error messages propagate OpenSSL details (HybridRsaCipher.cpp + publicCipher.ts:126,219,248)
- [HIGH] RSA Cipher — Prototype pollution in `preparePublicCipherKey`/`preparePrivateCipherKey`; `'key' in key` traverses prototype chain (publicCipher.ts:86-94,186)

**MEDIUM:**

- [MEDIUM] RSA Cipher — `double` to `int` cast for padding param; NaN/Infinity = UB (HybridRsaCipher.cpp:52)
- [MEDIUM] RSA Cipher — `publicDecrypt` returns empty buffer on certain error codes; broad `(err & 0xFF) == 0x04` match masks real failures (HybridRsaCipher.cpp:264)
- [MEDIUM] RSA Cipher — EVP_PKEY_CTX not RAII-wrapped; missed error paths leak context (HybridRsaCipher.cpp)
- [MEDIUM] RSA Cipher — No RSA padding constant validation; `padding: 99` sends invalid value to OpenSSL (publicCipher.ts:113)
- [MEDIUM] RSA Cipher — Error messages may enable padding oracle info leakage (publicCipher.ts:126,148,219,248)
- [MEDIUM] RSA Cipher — Default OAEP hash is SHA-1; deprecated but matches Node.js (publicCipher.ts:114,236)

**LOW:**

- [LOW] RSA Cipher — CryptoKey algorithm not validated as RSA before use (publicCipher.ts:63)
- [LOW] RSA Cipher — No RSA key size minimum enforcement at encrypt/decrypt time (HybridRsaCipher.cpp)
- [LOW] RSA Cipher — `RSA_NO_PADDING` not supported but not explicitly rejected with helpful message (HybridRsaCipher.cpp:17-26)

### Cross-Cutting (Symmetric Encryption)

**HIGH:**

- [HIGH] All Ciphers — `abvToArrayBuffer` ignores `byteOffset`/`byteLength`; sliced buffers pass wrong data to native (utils/conversion.ts:17-25)
- [HIGH] All Ciphers — `getUIntOption` uses `Record<string, any>` defeating type safety for options parsing (utils/cipher.ts:52)
- [HIGH] 3 Subclasses — CCMCipher, ChaCha20Cipher, ChaCha20Poly1305Cipher destructors leak EVP_CIPHER_CTX by nulling `ctx` before parent destructor

**MEDIUM:**

- [MEDIUM] All Ciphers — No algorithm name validation at TS boundary; invalid ciphers produce opaque native errors
- [MEDIUM] All Ciphers — `any` casts in stream options filtering (cipher.ts:103-104)
- [MEDIUM] All Ciphers — Double `binaryLikeToArrayBuffer` conversion in Cipheriv/Decipheriv constructors (cipher.ts:248-252)
- [MEDIUM] HybridCipherFactory — `EVP_CIPHER` leaked on exception during `cipherInstance->init()` (HybridCipherFactory.hpp:42-87)
- [MEDIUM] HybridCipherFactory — Switch fallthrough from `EVP_CIPH_STREAM_CIPHER` to `default` without `[[fallthrough]]` (HybridCipherFactory.hpp:80-88)

**LOW:**

- [LOW] HybridCipherFactory — `EVP_CIPHER_free(nullptr)` called after failed fetch; no-op but code smell (HybridCipherFactory.hpp:91)
- [LOW] cipher.ts — `authTagLen` defaults to 16 even for non-AEAD ciphers; harmless but unnecessary

### Test Coverage Gaps (Symmetric Encryption)

**HIGH:**

- [HIGH] AES-CBC — No NIST/RFC test vectors with known ciphertext verification; round-trip only
- [HIGH] AES-CBC — No wrong key/IV length rejection tests
- [HIGH] AES-GCM — No NIST SP 800-38D test vectors; correctness unverified against standard
- [HIGH] AES-GCM — No tag truncation / custom tag length tests
- [HIGH] AES-GCM — No wrong key/IV size rejection tests
- [HIGH] AES-CCM — Zero dedicated tests; most complex AEAD has only generic round-trip coverage
- [HIGH] AES-CCM — No tag verification failure test (CCM handles auth in `update`, not `final`)
- [HIGH] AES-CCM — No CCM-specific IV range validation test (7-13 bytes required)
- [HIGH] AES-OCB — Zero dedicated tests; custom init/getAuthTag/setAuthTag all untested
- [HIGH] AES-OCB — No tag tampering or authentication failure test
- [HIGH] XSalsa20 — Single round-trip test with no vectors, no key/nonce size rejection tests
- [HIGH] XSalsa20 — Oversized key silently accepted due to `<` vs `!=` in C++ validation
- [HIGH] RSA — No cross-padding-mode failure test (OAEP encrypt → PKCS1 decrypt should fail)
- [HIGH] All AEAD — No test for `setAAD` after `update` (must error)
- [HIGH] All AEAD — No test for `getAuthTag` on decipher (must error)
- [HIGH] All AEAD — No test for `setAuthTag` on cipher (must error)

**MEDIUM:**

- [MEDIUM] AES-CBC — No empty plaintext test (exercises padding-only output)
- [MEDIUM] AES-CBC — No `setAutoPadding` test
- [MEDIUM] AES-GCM — No tampered AAD test (modified AAD should cause auth failure)
- [MEDIUM] AES-GCM — No test for missing `setAuthTag` on decrypt
- [MEDIUM] AES-GCM — No test for `getAuthTag` before `final()`
- [MEDIUM] AES-CCM — No custom tag length test (4-16 even values)
- [MEDIUM] AES-OCB — No custom tag length test (8-16 bytes)
- [MEDIUM] AES-OCB — No wrong tag length rejection test
- [MEDIUM] ChaCha20 — No wrong key size rejection test (32 bytes required)
- [MEDIUM] ChaCha20 — RFC vectors only cover encryption direction; no standalone decryption test
- [MEDIUM] ChaCha20-Poly1305 — No wrong key size rejection test
- [MEDIUM] ChaCha20-Poly1305 — No tag tampering test
- [MEDIUM] ChaCha20-Poly1305 — No tampered ciphertext test
- [MEDIUM] ChaCha20-Poly1305 — Custom tag length tests may be silently wrong; C++ always uses 16 bytes
- [MEDIUM] XChaCha20-Poly1305 — No tampered ciphertext test (only wrong tag tested)
- [MEDIUM] XSalsa20 — Uses standalone `xsalsa20()` not `createCipheriv`; path untested
- [MEDIUM] XSalsa20-Poly1305 — "Test vector" only does round-trip; no known-answer comparison
- [MEDIUM] RSA — No unsupported padding constant rejection test
- [MEDIUM] RSA — No malformed ciphertext test for `privateDecrypt`
- [MEDIUM] RSA — No wrong key type test (`publicEncrypt` with private key behavior undefined)
- [MEDIUM] All modules — No key/IV type validation tests (null, undefined, number as key)
- [MEDIUM] All modules — Generic round-trip error catch converts all errors to `expect.fail`, masking root cause

**LOW:**

- [LOW] AES-CBC — No stream interface tests (pipe/transform API)
- [LOW] AES-CTR/CFB/OFB/ECB — No mode-specific edge case tests
- [LOW] AES-GCM — No empty AAD test
- [LOW] ChaCha20 — Silently catches 64-bit nonce failure with bare `catch {}` (chacha_tests.ts:310-313)
- [LOW] XChaCha20-Poly1305 — Only one IETF test vector; additional Wycheproof vectors would strengthen confidence
- [LOW] XSalsa20-Poly1305 — No tampered ciphertext test (only tag mismatch tested)
- [LOW] RSA — No minimum key size test (1024-bit)
- [LOW] All modules — No multi-chunk `update()` tests (all tests use single update call)

### PBKDF2

**HIGH:**

- [HIGH] PBKDF2 — No return value check on `PKCS5_PBKDF2_HMAC`; failed derivation silently returns uninitialized buffer (HybridPbkdf2.cpp:44)
- [HIGH] PBKDF2 — No return value check on `fastpbkdf2_hmac_*` calls; failure returns uninitialized heap data as derived key material (HybridPbkdf2.cpp:27-34)
- [HIGH] PBKDF2 — Raw `new uint8_t[]` without RAII guard; leak if `make_shared` throws (HybridPbkdf2.cpp:22-23)
- [HIGH] PBKDF2 — `keylen=0` not rejected at C++ layer; `new uint8_t[0]` is implementation-defined (HybridPbkdf2.cpp:21-22)

**MEDIUM:**

- [MEDIUM] PBKDF2 — `double` to `uint32_t` truncation for iterations unchecked at C++ layer (HybridPbkdf2.cpp:28)
- [MEDIUM] PBKDF2 — Derived key material never zeroed; `delete[]` without `OPENSSL_cleanse` (HybridPbkdf2.cpp:23)
- [MEDIUM] PBKDF2 — `password.get()->data()` dereference without null check; null ArrayBuffer = UB (HybridPbkdf2.cpp:27)
- [MEDIUM] PBKDF2 — No digest validation at C++ layer; unknown digests silently fall through to OpenSSL path (HybridPbkdf2.cpp:26-45)

**LOW:**

- [LOW] PBKDF2 — `reinterpret_cast<char*>` discards const; should be `const char*` (HybridPbkdf2.cpp:41)
- [LOW] PBKDF2 — Async test assertions inside callback are fire-and-forget; failures silently swallowed (pbkdf2_tests.ts:30-35)

### Scrypt

**HIGH:**

- [HIGH] Scrypt — No validation of `N` being a power of 2 per RFC 7914; OpenSSL rejects with opaque error (scrypt.ts:38-45)
- [HIGH] Scrypt — No upper-bound validation of N, r, p; `N=2^30, r=8, p=1` requires ~1TB memory (scrypt.ts:38-45)
- [HIGH] Scrypt — `keylen=0` passes TS validation but C++ throws; inconsistent with Node.js which returns empty Buffer (scrypt.ts:88, HybridScrypt.cpp:36-38)

**MEDIUM:**

- [MEDIUM] Scrypt — Derived key material never zeroed before deallocation (HybridScrypt.cpp:59)
- [MEDIUM] Scrypt — `double` to `uint64_t` truncation unchecked; negative doubles wrap to large positive values (HybridScrypt.cpp:30-34)
- [MEDIUM] Scrypt — No `keylen` upper-bound validation; massive allocation possible (scrypt.ts:88,119)
- [MEDIUM] Scrypt — `maxmem` default of 32MB may OOM mobile devices; no documentation (scrypt.ts:35)

**LOW:**

- [LOW] Scrypt — Missing `Number.isInteger(keylen)` check; float values truncated silently (scrypt.ts:88)
- [LOW] Scrypt — Error in async path casts to `Error` with `err as Error`; OpenSSL errors may be strings (scrypt.ts:103)

### HKDF

**HIGH:**

- [HIGH] HKDF — No maximum output length validation per RFC 5869; must not exceed `255 * HashLen` (hkdf.ts:64, HybridHkdf.cpp:77-81)
- [HIGH] HKDF — Passing `nullptr` to `OSSL_PARAM_construct_octet_string` for empty key; may segfault (HybridHkdf.cpp:57)
- [HIGH] HKDF — `OSSL_PARAM params[5]` array exactly full; any additional param would overflow (HybridHkdf.cpp:44)

**MEDIUM:**

- [MEDIUM] HKDF — `keylen=0` allowed by TS but rejected by C++; inconsistent with Node.js (hkdf.ts:64)
- [MEDIUM] HKDF — Derived key material not zeroed before deallocation (HybridHkdf.cpp:93)
- [MEDIUM] HKDF — `hkdfDeriveBits` returns ArrayBuffer directly; `Math.ceil(length / 8)` excess bytes not trimmed (hkdf.ts:132,146)
- [MEDIUM] HKDF — Error reporting uses raw `ERR_get_error()` numeric code, not human-readable string (HybridHkdf.cpp:34,40,88)
- [MEDIUM] HKDF — Salt silently omitted when empty; RFC 5869 defaults to `HashLen` zeros; behavior undocumented (HybridHkdf.cpp:60-66)

**LOW:**

- [LOW] HKDF — `keylen` not validated as integer; float values silently truncated (hkdf.ts:64)
- [LOW] HKDF — Empty info buffer silently omitted; RFC 5869 defaults to empty string (HybridHkdf.cpp:70-72)

### Argon2

**HIGH:**

- [HIGH] Argon2 — No RFC 9106 parameter validation: min salt 8 bytes, min tag 4 bytes, min memory `8*parallelism` KiB, min passes 1, min parallelism 1 (argon2.ts:43-58, HybridArgon2.cpp:26-60)
- [HIGH] Argon2 — `double` to `uint32_t` truncation for parallelism/memory/passes/version; NaN/Infinity/negative = UB (HybridArgon2.cpp:50)
- [HIGH] Argon2 — `tagLength` cast from `double` to `size_t` can produce huge allocations (HybridArgon2.cpp:50)

**MEDIUM:**

- [MEDIUM] Argon2 — No version validation; only `0x10` and `0x13` are defined per RFC 9106 (argon2.ts:45, HybridArgon2.cpp:50)
- [MEDIUM] Argon2 — Derived key material not zeroed; neither ncrypto buffer nor copy are cleansed (HybridArgon2.cpp:59)
- [MEDIUM] Argon2 — `hashSync` passes original shared_ptrs without copying; potential use-after-free edge case (HybridArgon2.cpp:97)
- [MEDIUM] Argon2 — Error message may expose OpenSSL internal reason strings (HybridArgon2.cpp:54-56)

**LOW:**

- [LOW] Argon2 — Algorithm name string echoed in error message (HybridArgon2.cpp:23)
- [LOW] Argon2 — `argon2d` exposed without warning; vulnerable to side-channel attacks (argon2.ts:29-37)

### Test Coverage Gaps (Key Derivation)

**HIGH:**

- [HIGH] PBKDF2 — Async test assertions inside callbacks are fire-and-forget; failures silently swallowed (pbkdf2_tests.ts:30-35)
- [HIGH] Scrypt — No negative/error-path tests: invalid N (not power of 2), N=0, r=0, p=0, negative params (scrypt_tests.ts)
- [HIGH] HKDF — Only 1 of 7 RFC 5869 test vectors implemented; missing zero-length salt/info case (hkdf_tests.ts:8-17)
- [HIGH] HKDF — No tests for empty salt, empty info, or empty key; critical RFC 5869 edge cases (hkdf_tests.ts)
- [HIGH] Argon2 — RFC 9106 test vector output not verified; only checks `result.length === 32`, not actual bytes (argon2_tests.ts:23-27)
- [HIGH] Argon2 — No error-path tests for invalid parameters: zero parallelism, zero memory, short salt, NaN (argon2_tests.ts)

**MEDIUM:**

- [MEDIUM] PBKDF2 — No test for `keylen=0`; Node.js returns empty Buffer (pbkdf2_tests.ts)
- [MEDIUM] HKDF — No negative/error-path tests: invalid digest, negative keylen, keylen exceeding 255\*HashLen (hkdf_tests.ts)
- [MEDIUM] Scrypt — Missing RFC 7914 Test Case 4 (N=1048576, r=8, p=1); should be documented (scrypt_tests.ts:12-43)
- [MEDIUM] All KDFs — No cross-validation tests with Node.js `crypto` module output

**LOW:**

- [LOW] PBKDF2 — Test at line 100-106 labeled "should throw if password not string/ArrayBuffer" actually tests "No callback provided" (pbkdf2_tests.ts:97-106)

### Diffie-Hellman

**HIGH:**

- [HIGH] DH — No minimum prime size enforcement when custom prime provided via `init()`; accepts dangerously small primes (HybridDiffieHellman.cpp:25)
- [HIGH] DH — No validation of peer public key in `computeSecret()`; 0, 1, or p-1 enable small subgroup attacks (HybridDiffieHellman.cpp:129-213)
- [HIGH] DH — Shared secret in `std::vector<uint8_t>` not zeroed on destruction; persists in heap (HybridDiffieHellman.cpp:204)
- [HIGH] DhKeyPair — No minimum prime size enforcement in `generateKeyPairSync()` unlike `HybridDiffieHellman::initWithSize()` (HybridDhKeyPair.cpp:85-107)

**MEDIUM:**

- [MEDIUM] DH — `double` to `int` cast for `primeLength` and `generator` without range validation; NaN/Infinity = UB (HybridDhKeyPair.cpp:27-28,35-36)
- [MEDIUM] DH — Private key material not zeroed on destruction; BIGNUM temporaries freed with `BN_free` not `BN_clear_free` (HybridDiffieHellman.cpp:355-425)
- [MEDIUM] DH — No generator validation; generator 0 or 1 produces degenerate keys (HybridDiffieHellman.cpp:25-64)
- [MEDIUM] DH — Missing named groups; only modp14-18 defined; no groups with known subgroup order (dh-groups.ts)
- [MEDIUM] DH — `createDiffieHellman` default encoding 'utf8' inconsistent with Node.js 'binary' (diffie-hellman.ts:156)

**LOW:**

- [LOW] DH — BIO resource management uses manual `BIO_free` instead of RAII; leak on exception (HybridDhKeyPair.cpp:137-175)
- [LOW] DH — `generateKeyPair()` captures `this` in async lambda; use-after-free if object destroyed (HybridDhKeyPair.cpp:40)
- [LOW] DH — `ToNativeArrayBuffer` uses raw `new uint8_t[]` with lambda deleter (QuickCryptoUtils.hpp:38-41)

### ECDH

**HIGH:**

- [HIGH] ECDH — No explicit point-on-curve validation for peer public key in `computeSecret()`; invalid-curve attack possible (HybridECDH.cpp:62-100)
- [HIGH] ECDH — No validation of private key range [1, n-1] in `setPrivateKey()`; key of 0 produces point at infinity (HybridECDH.cpp:120-149)
- [HIGH] ECDH — Shared secret `std::vector<uint8_t>` not securely erased before destruction (HybridECDH.cpp:92-99)

**MEDIUM:**

- [MEDIUM] ECDH — `setPublicKey()` does not validate point is on configured curve (HybridECDH.cpp:169-174)
- [MEDIUM] ECDH — No curve restriction/allowlist; weak/deprecated curves accepted via `OBJ_txt2nid` (HybridECDH.cpp:217-226)
- [MEDIUM] ECDH — `double format` cast to `point_conversion_form_t` without validation at C++ layer (HybridECDH.cpp:176-209)
- [MEDIUM] ECDH — Private key bytes from `getPrivateKey()` not padded to curve field size; interop issues (HybridECDH.cpp:102-118)
- [MEDIUM] ECDH — `createEcEvpPkey()` does not check return values of `OSSL_PARAM_BLD_push_*` calls (QuickCryptoUtils.cpp:15-18)

**LOW:**

- [LOW] ECDH — `_curveNid` initialized to 0 (`NID_undef`); magic number dependency (HybridECDH.hpp:37)
- [LOW] ECDH — Static singleton `_convertKeyHybrid` lazily created, never destroyed (ecdh.ts:11-18)
- [LOW] ECDH — `getPublicKey()` ignores `format` parameter; no compressed/hybrid format support (ecdh.ts:69)

### Test Coverage Gaps (Key Exchange)

**HIGH:**

- [HIGH] DH — No invalid public key test; 0, 1, or p-1 (small subgroup attack vectors) not tested
- [HIGH] ECDH — No invalid public key test; point not on curve and identity point untested
- [HIGH] ECDH — No private key range test; value 0 or >= curve order n untested

**MEDIUM:**

- [MEDIUM] DH — No weak prime test; non-safe prime detection via `verifyError` untested
- [MEDIUM] ECDH — No cross-curve test; Alice P-256 / Bob P-384 `computeSecret` behavior untested
- [MEDIUM] DH/ECDH — No empty input test for `computeSecret`, `setPublicKey`, `setPrivateKey`
- [MEDIUM] DH — No NIST/RFC known-answer tests; only checks Alice == Bob
- [MEDIUM] ECDH — No NIST CAVP or RFC 5903 test vectors; only checks Alice == Bob
- [MEDIUM] DhKeyPair — `DhKeyPairGen` class has no dedicated tests at all

**LOW:**

- [LOW] ECDH — No weak curve test (e.g., prime192v1)
- [LOW] DH — No string encoding roundtrip test through `computeSecret`

### Sign/Verify (Generic Interface)

**HIGH:**

- [HIGH] Sign/Verify — Raw `EVP_PKEY*` via `GetAsymmetricKey().get()` with no reference-count guarantee during async operations (HybridSignHandle.cpp:127, HybridVerifyHandle.cpp:126)
- [HIGH] Sign/Verify — No validation that key type matches operation; C++ accepts any key (HybridSignHandle.cpp:119-131, HybridVerifyHandle.cpp:119-130)
- [HIGH] Sign/Verify — `EVP_PKEY_CTX` double-free risk on partial `EVP_DigestSignInit` failure (HybridSignHandle.cpp:150-165)

**MEDIUM:**

- [MEDIUM] Sign/Verify — Unbounded `data_buffer` accumulation in streaming mode; DoS vector (HybridSignHandle.hpp:33, HybridVerifyHandle.hpp:33)
- [MEDIUM] Sign/Verify — No re-use protection; calling `sign()`/`verify()` twice on finalized context = UB (HybridSignHandle.cpp:194)

**LOW:**

- [LOW] Sign/Verify — Error message leaks key type info and internal constants (HybridSignHandle.cpp:206-208)
- [LOW] Sign/Verify — `size_t` to `int` narrowing in `BN_bn2binpad` (SignUtils.hpp:50,64)

### ECDSA (EC Key Pairs)

**HIGH:**

- [HIGH] ECDSA — No curve validation for Node.js API key generation; arbitrary curve names accepted including weak curves (ec.ts:382-396, HybridEcKeyPair.cpp:317)
- [HIGH] ECDSA — Raw `EVP_PKEY*` without RAII; violates project smart-pointer mandate (HybridEcKeyPair.hpp:44)
- [HIGH] ECDSA — BIO not checked for null before `i2d_PKCS8PrivateKey_bio`; null = UB (HybridEcKeyPair.cpp:286)

**MEDIUM:**

- [MEDIUM] ECDSA — SHA-1 allowed for ECDSA signing; WebCrypto spec recommends rejection (HybridEcKeyPair.cpp:343)
- [MEDIUM] ECDSA — Private key DER data in `std::string` not zeroed before destruction (HybridEcKeyPair.cpp:210-211,290-291)
- [MEDIUM] ECDSA — `importKey` tries multiple parsing strategies without clearing error queue between attempts (HybridEcKeyPair.cpp:131-166)

**LOW:**

- [LOW] ECDSA — Signature malleability (high-S) not enforced; DER-encoded ECDSA signatures malleable by design (SignUtils.hpp:42-53)

### Ed25519/Ed448

**HIGH:**

- [HIGH] Ed25519/Ed448 — Memory leak for imported keys; `EVP_PKEY*` created in `importPublicKey`/`importPrivateKey` never freed by callers (HybridEdKeyPair.cpp:356-401, callers at :155,:221)
- [HIGH] Ed25519/Ed448 — Double-free risk with `EVP_PKEY_CTX` in `signSync` on partial `EVP_DigestSignInit` failure (HybridEdKeyPair.cpp:163-173)
- [HIGH] Ed25519/Ed448 — `ERR_error_string(ERR_get_error(), NULL)` uses thread-unsafe static buffer (HybridEdKeyPair.cpp:172,241)

**MEDIUM:**

- [MEDIUM] Ed25519/Ed448 — Raw `new`/`delete` throughout; violates C++20 smart-pointer mandate (HybridEdKeyPair.cpp:58,181,282-284,295-296,339-340)
- [MEDIUM] Ed25519/Ed448 — Private key raw bytes not zeroed; `delete[]` without `OPENSSL_cleanse` (HybridEdKeyPair.cpp:339-343)
- [MEDIUM] Ed25519/Ed448 — Incomplete curve name normalization; `"ED25519"` uppercase not handled (HybridEdKeyPair.cpp:359-366)
- [MEDIUM] Ed25519/Ed448 — `cipher`/`passphrase` parameters accepted but ignored; encrypted export silently doesn't encrypt (HybridEdKeyPair.cpp:84-86)

**LOW:**

- [LOW] Ed25519/Ed448 — No validation of raw key sizes before `EVP_PKEY_new_raw_public_key`; generic error (HybridEdKeyPair.cpp:369)

### RSA (PKCS1-v1.5, PSS) Key Generation

**HIGH:**

- [HIGH] RSA KeyGen — Minimum modulus length 256 bits is trivially factorable; NIST minimum is 2048 (rsa.ts:73,201)

**MEDIUM:**

- [MEDIUM] RSA KeyGen — Raw `EVP_PKEY*` without RAII; violates smart-pointer mandate (HybridRsaKeyPair.hpp:35)
- [MEDIUM] RSA KeyGen — Private key DER data in `std::string` not zeroed (HybridRsaKeyPair.cpp:132)
- [MEDIUM] RSA KeyGen — Public exponent not validated; exponents of 1 or even numbers produce degenerate keys (HybridRsaKeyPair.cpp:57)
- [MEDIUM] RSA KeyGen — `hashAlgorithm` stored but unused in key generation; RSA-PSS keys lack restricted parameters (HybridRsaKeyPair.cpp:86-88)

**LOW:**

- [LOW] RSA KeyGen — `double` to `int` truncation for `modulusLength` unchecked (HybridRsaKeyPair.cpp:76)

### DSA

**HIGH:**

- [HIGH] DSA — No minimum modulus length validation; `modulusLength=512` accepted; FIPS 186-4 requires 1024+ (HybridDsaKeyPair.cpp:29, dsa.ts:37)

**MEDIUM:**

- [MEDIUM] DSA — No validation of `divisorLength` against FIPS 186-4 (L,N) pairs: (1024,160), (2048,224), (2048,256), (3072,256) (HybridDsaKeyPair.cpp:50-53)
- [MEDIUM] DSA — DSA deprecated in FIPS 186-5 (2023); no warning or deprecation notice to users

**LOW:**

- [LOW] DSA — Private key DER data in `std::string` not zeroed (HybridDsaKeyPair.cpp:121-122)

### Test Coverage Gaps (Digital Signatures)

**HIGH:**

- [HIGH] All Signatures — No NIST/RFC test vector validation; all tests use self-generated keys/signatures
- [HIGH] All Signatures — No cross-implementation verification (Node.js crypto → RNQC or vice versa)
- [HIGH] ECDSA — No signature malleability tests (high-S value handling)
- [HIGH] Ed25519/Ed448 — No tests with wrong-type key (e.g., X25519 key for Ed25519 sign)
- [HIGH] Ed448 — No signing tests at all; only key generation and export tested
- [HIGH] RSA — No key size boundary tests; 512-bit or 1024-bit key generation not tested for rejection

**MEDIUM:**

- [MEDIUM] DSA — No tests for `dsaEncoding: 'ieee-p1363'` format
- [MEDIUM] All — No empty-message signing tests
- [MEDIUM] RSA-PSS — No salt length edge case tests (`RSA_PSS_SALTLEN_DIGEST`, `RSA_PSS_SALTLEN_MAX_SIGN`)
- [MEDIUM] All — No concurrent/parallel signing tests (thread-safety of `ERR_error_string` static buffer)

### ML-DSA (44/65/87)

**HIGH:**

- [HIGH] ML-DSA — Double-free risk on `EVP_PKEY_CTX` in `signSync`/`verifySync`; ownership ambiguous after partial `EVP_DigestSignInit` failure (HybridMlDsaKeyPair.cpp:180-182,231-233)
- [HIGH] ML-DSA — Unnecessary `EVP_PKEY_CTX_new_from_name` before `EVP_DigestSignInit`; pre-created context with wrong algorithm = UB (HybridMlDsaKeyPair.cpp:174,225)

**MEDIUM:**

- [MEDIUM] ML-DSA — No RAII for `EVP_MD_CTX` and manual `new[]`/`delete[]` for signature buffers (HybridMlDsaKeyPair.cpp:169,192)
- [MEDIUM] ML-DSA — Raw `this` capture in `Promise::async` lambdas; use-after-free if object destroyed (HybridMlDsaKeyPair.cpp:42,159,210)
- [MEDIUM] ML-DSA — No FIPS 204 context string support; applications cannot use domain separation (HybridMlDsaKeyPair.cpp:162-203)
- [MEDIUM] ML-DSA — `setVariant` lacks `#else` guard; throw doesn't prevent compilation of unreachable code (HybridMlDsaKeyPair.cpp:31-33)
- [MEDIUM] ML-DSA — `double` parameters for format/type enums cast to `int` without range/NaN checking (HybridMlDsaKeyPair.cpp:57-60)

**LOW:**

- [LOW] ML-DSA — `getEvpPkeyType()` defined but never called; dead code (HybridMlDsaKeyPair.cpp:18-28)
- [LOW] ML-DSA — Private key export always unencrypted; no cipher/passphrase support (HybridMlDsaKeyPair.cpp:134)
- [LOW] ML-DSA — Private key bytes in BIO buffers not zeroed before `delete[]` (HybridMlDsaKeyPair.cpp:145-153)

### ML-KEM (512/768/1024)

**HIGH:**

- [HIGH] ML-KEM — Shared secret not zeroed after use in `encapsulateSync`; raw `sharedKey` ArrayBuffer may be long-lived (HybridMlKemKeyPair.cpp:246-264, subtle.ts:2778)
- [HIGH] ML-KEM — No key type validation in `_encapsulateCore`/`_decapsulateCore`; no check that key is public/private (subtle.ts:2752-2809)

**MEDIUM:**

- [MEDIUM] ML-KEM — No RAII for `EVP_PKEY_CTX` in encapsulate/decapsulate (HybridMlKemKeyPair.cpp:226-264,280-311)
- [MEDIUM] ML-KEM — Raw `this` capture in `Promise::async` lambdas (HybridMlKemKeyPair.cpp:29,216,270)
- [MEDIUM] ML-KEM — `BIO_new_mem_buf` casts `size_t` to `int` for key data size (HybridMlKemKeyPair.cpp:158,191)
- [MEDIUM] ML-KEM — `setPublicKey` overwrites entire `pkey_` including private key; subsequent `decapsulate` fails confusingly (HybridMlKemKeyPair.cpp:176)
- [MEDIUM] ML-KEM — Packed encapsulation result uses native byte order `memcpy` for `uint32_t` but TS unpacks as little-endian; breaks on big-endian (HybridMlKemKeyPair.cpp:250-251, mlkem.ts:51)

**LOW:**

- [LOW] ML-KEM — No validation that imported key matches configured variant (HybridMlKemKeyPair.cpp:145-178)
- [LOW] ML-KEM — Decapsulated shared secret not zeroed before `delete[]` (HybridMlKemKeyPair.cpp:299-309)

### Test Coverage Gaps (Post-Quantum)

**HIGH:**

- [HIGH] ML-DSA/ML-KEM — No NIST Known-Answer Tests (KAT); all tests are round-trip only
- [HIGH] ML-DSA/ML-KEM — No cross-parameter-set rejection tests (e.g., ML-DSA-44 key vs ML-DSA-65 signature)
- [HIGH] ML-KEM — No invalid ciphertext tests; FIPS 203 implicit rejection behavior untested

**MEDIUM:**

- [MEDIUM] ML-DSA — No context string tests (API does not support context strings)
- [MEDIUM] ML-KEM — No `encapsulateKey`/`decapsulateKey` end-to-end test using derived AES key for actual encryption
- [MEDIUM] ML-DSA/ML-KEM — No non-extractable key export rejection tests

### KeyObjectHandle

**HIGH:**

- [HIGH] KeyObjectHandle — 32-byte raw key unconditionally assumed X25519; Ed25519 keys silently misidentified (HybridKeyObjectHandle.cpp:757-759)
- [HIGH] KeyObjectHandle — Private key export has no access control; no mechanism to mark keys non-exportable (HybridKeyObjectHandle.cpp:90-216)

**MEDIUM:**

- [MEDIUM] KeyObjectHandle — Deprecated RSA API usage: `EVP_PKEY_get0_RSA()`, `RSA_new()`, `RSA_set0_key()` etc. (HybridKeyObjectHandle.cpp:241-248,507-509)
- [MEDIUM] KeyObjectHandle — BIGNUM memory leak in JWK EC import error path; partial null results leak decoded BIGNUMs (HybridKeyObjectHandle.cpp:547-553)
- [MEDIUM] KeyObjectHandle — `base64url_to_bn` returns raw `BIGNUM*` without ownership semantics; error-prone (HybridKeyObjectHandle.cpp:51)
- [MEDIUM] KeyObjectHandle — OpenSSL error details leaked in error messages (KeyObjectData.cpp:49-53,143-146,169-171)

**LOW:**

- [LOW] KeyObjectHandle — `setKeyObjectData` is public with no validation (HybridKeyObjectHandle.hpp:48-49)
- [LOW] KeyObjectHandle — `keyDetail` returns empty struct for non-RSA/non-EC keys (HybridKeyObjectHandle.cpp:709-749)

### Random (CSPRNG)

**HIGH:**

- [HIGH] Random — `pow(2, 31) - 1` floating-point comparison for max size; should use `INT32_MAX` (HybridRandom.cpp:12,42)

**MEDIUM:**

- [MEDIUM] Random — `abvToArrayBuffer` returns full backing buffer; native layer receives larger-than-expected buffer (conversion.ts:17-25, random.ts:80-88)
- [MEDIUM] Random — Debug `printData` function left in header; prints raw byte data to stdout (HybridRandom.hpp:24-31)

**LOW:**

- [LOW] Random — `checkSize` uses floating-point `pow` for integer comparison (HybridRandom.cpp:12)
- [LOW] Random — `CheckIsUint32(1.5)` returns true; non-integer values not rejected (QuickCryptoUtils.hpp:63-65)

### Prime

**MEDIUM:**

- [MEDIUM] Prime — No validation of bit size parameter; 0, negative, or huge values passed to `BN_generate_prime_ex2` (HybridPrime.cpp:18, prime.ts)
- [MEDIUM] Prime — `checkPrime` default `checks=0` meaning ("use OpenSSL default") not documented (prime.ts:105)

**LOW:**

- [LOW] Prime — `rem` without `add` silently ignored; matches Node.js but confusing (HybridPrime.cpp:16-35)

### Certificate / SPKAC

**LOW:**

- [LOW] Certificate — No size validation on SPKAC input; extremely large input = excessive allocation (HybridCertificate.cpp:8-40)
- [LOW] Certificate — `OPENSSL_free(buf.data)` leaks if `ToNativeArrayBuffer` throws (HybridCertificate.cpp:29-39)

### X.509

**MEDIUM:**

- [MEDIUM] X.509 — No null check on `cert_` member before method calls; crash if `init()` never called (HybridX509Certificate.cpp:27-95)
- [MEDIUM] X.509 — `validFromDate`/`validToDate` cast `time_t` to `double` × 1000; precision safe for practical dates (HybridX509Certificate.cpp:51-57)

**LOW:**

- [LOW] X.509 — `fingerprint()` uses SHA-1; provided for compatibility, `fingerprint256`/`fingerprint512` also available (HybridX509Certificate.cpp:78)
- [LOW] X.509 — TypeScript caches immutable properties but never clears cache (x509certificate.ts:91-98)

### Utils / Conversions

**HIGH:**

- [HIGH] Utils — `timingSafeEqual` uses `abvToArrayBuffer` which returns entire backing buffer; TypedArray views compare wrong data (timingSafeEqual.ts:15-16, conversion.ts:17-25)

**MEDIUM:**

- [MEDIUM] Utils — `abvToArrayBuffer` does not respect `byteOffset`/`byteLength` for TypedArray views; also used in `timingSafeEqual` (conversion.ts:17-25)
- [MEDIUM] Utils — `binaryLikeToArrayBuffer` duck-typing uses `Symbol.toStringTag === 'KeyObject'`; any object with this tag triggers `.handle.exportKey()` (conversion.ts:142-151)

**LOW:**

- [LOW] Utils — `decodeLatin1` does not validate UTF-8 continuation bytes have `10xxxxxx` pattern (HybridUtils.cpp:118-145)

### Test Coverage Gaps (Key Management & Utilities)

**HIGH:**

- [HIGH] Utils — No tests for `timingSafeEqual` with TypedArray views over larger buffers (backing buffer vs view comparison)
- [HIGH] Random — Async randomFill tests swallow exceptions; failures silently ignored (random_tests.ts:53-68,70-85)

**MEDIUM:**

- [MEDIUM] KeyObjectHandle — No tests for encrypted private key export/import (cipher/passphrase params untested)
- [MEDIUM] Prime — No negative tests: `generatePrimeSync(0)`, `generatePrimeSync(-1)`, `generatePrimeSync(2)`
- [MEDIUM] KeyObjectHandle — No tests for OKP (Ed25519/X25519) JWK round-trip
- [MEDIUM] Random — No test for `randomUUID` format correctness (version 4 and RFC 4122 variant bits)
- [MEDIUM] X.509 — No tests for malformed certificates, truncated DER, expired certs, critical extensions

**LOW:**

- [LOW] Random — No test for `getRandomValues` exceeding 65536 bytes
- [LOW] KeyObjectHandle — No `keyEquals` test for private keys being equal

### WebCrypto Subtle

**HIGH:**

- [HIGH] Subtle — `normalizeAlgorithm` does not perform case-insensitive matching per WebCrypto spec; `"aes-gcm"` bypasses `SUPPORTED_ALGORITHMS` (subtle.ts:86-94)
- [HIGH] Subtle — Key material exported to plaintext via `key.keyObject.export()` for every encrypt/decrypt; "non-extractable" keys transit through JS memory (subtle.ts:261,302,349,477,540)
- [HIGH] Subtle — `deriveBits` accepts `deriveKey` usage as substitute for `deriveBits`; violates spec usage enforcement (subtle.ts:2164-2169)
- [HIGH] Subtle — `hkdfImportKey` does not enforce `extractable === false` per WebCrypto spec (subtle.ts:1583-1603)
- [HIGH] Subtle — `exportKeyRaw` does not enforce key type for symmetric algorithms (subtle.ts:1445-1468)

**MEDIUM:**

- [MEDIUM] Subtle — `as unknown as` casts bypass type safety (subtle.ts:2184,2238,2488)
- [MEDIUM] Subtle — Return types `ArrayBuffer | unknown` on export functions; `unknown` union = no type safety (subtle.ts:1282,1346,1408,1477)
- [MEDIUM] Subtle — No AES-GCM IV length validation; spec recommends 12 bytes, disallows 0 (subtle.ts:398-417)
- [MEDIUM] Subtle — RSA import does not validate public key usages vs private key usages (subtle.ts:868-971)
- [MEDIUM] Subtle — JWK import does not validate `jwk.ext` against `extractable` parameter per spec (subtle.ts:897-919,987-1023,1064-1080)
- [MEDIUM] Subtle — JWK import does not validate `jwk.key_ops` against `usages` parameter per spec (subtle.ts:897-919)
- [MEDIUM] Subtle — `cipherOrWrap` switch has no `default`; returns `undefined` typed as `Promise<ArrayBuffer>` (subtle.ts:1856-1896)
- [MEDIUM] Subtle — `AnyAlgorithm` includes `'unknown'` as valid value (types.ts:223)
- [MEDIUM] Subtle — `edImportKey` raw format does not restrict usages to public-only (subtle.ts:1156-1164)
- [MEDIUM] Subtle — Enums used despite project rules prohibiting them (subtle.ts:70-79, types.ts:274-298)

**LOW:**

- [LOW] Subtle — `EncodingOptions.key` typed as `any` (types.ts:365)
- [LOW] Subtle — Multiple `as` casts without runtime validation: `data as JWK`, `data as BufferLike`, `data as BinaryLike` (subtle.ts:898,922,930,988,1025,1065,1086,1140,1166)
- [LOW] Subtle — Error messages inconsistent: some use `lazyDOMException`, others use plain `new Error()` (subtle.ts:889,892,901,938)
- [LOW] Subtle — `getKeyLength` uses `||` instead of `??`; explicit `0` falls through to default (subtle.ts:2904,2908,2912,2913)
- [LOW] Subtle — `hmacGenerateKey` defaults to 256 bits for unknown hash algorithms silently (subtle.ts:680)

### Test Coverage Gaps (WebCrypto Subtle)

**HIGH:**

- [HIGH] Subtle — No tests for non-extractable key export rejection; `key.extractable` check at line 2283 untested
- [HIGH] Subtle — No cross-algorithm key confusion tests (e.g., AES-GCM key used with AES-CBC)
- [HIGH] Subtle — No tests for JWK `ext` and `key_ops` validation during import
- [HIGH] Subtle — HKDF `extractable: false` enforcement not tested (implementation also doesn't enforce it)
- [HIGH] Subtle — AES/HMAC generateKey tests largely commented out (generateKey.ts:46-68,647-815)

**MEDIUM:**

- [MEDIUM] Subtle — No algorithm name case sensitivity tests
- [MEDIUM] Subtle — No negative tests for `deriveBits` with wrong key usage
- [MEDIUM] Subtle — No AES-GCM tests with unusual IV lengths (empty, very long)
- [MEDIUM] Subtle — No RSA key type vs usage mismatch tests during import
- [MEDIUM] Subtle — No wrap/unwrap negative tests (non-extractable key, wrong algorithm, corrupted data)
- [MEDIUM] Subtle — No HKDF `deriveBits`/`deriveKey` tests in subtle test suite

**LOW:**

- [LOW] Subtle — `getPublicKey` tests do not cover ML-DSA or ML-KEM
- [LOW] Subtle — No `subtle.supports()` tests for `encapsulateBits`/`decapsulateBits` operations
- [LOW] Subtle — Digest tests do not test error cases (invalid algorithm, null data)

---

## Implementation Plan

The scan surfaces ~120 HIGH / ~180 MEDIUM / ~50 LOW findings across 32 modules, but the **Recurring Patterns** table collapses these to roughly **15 root causes**. The plan is sequenced so each phase unblocks the next and shared fixes close many findings at once.

Status key: `[ ]` not started · `[~]` in progress · `[x]` complete

### Phase Execution Rules

These rules apply to every phase below. Follow them on every multi-task phase, not just the first.

1. **Commit after each sub-section, not at the end of the phase.** A "sub-section" is a single numbered task (e.g. 0.1, 1.2, 2.3) or a single logical wave inside a sweep (e.g. Wave 1A: digests). Each commit should be self-contained, reviewable, and revertable on its own. Do **not** batch a whole phase into one commit — that loses bisectability and makes review harder.
2. **Do NOT push or open a PR until the user has run the example app's tests locally and reported pass/fail.** Tests live in `example/src/tests/` and run inside the React Native example app, not under any Node.js test runner. Pre-commit hooks only cover lint, format, tsc, and bob build — they cannot exercise the native bridge. Wait for explicit user confirmation ("tests pass") before `git push -u` or `gh pr create`. If tests fail, fix in place on the local branch and re-request a test run.
3. **CI gate**: PRs must run the full CI matrix — `Validate C++`, `Validate JS`, `End-to-End Tests for Android`, `End-to-End Tests for iOS`. If a path-filtered workflow doesn't trigger on a C++-only or TS-only PR, fix the workflow's `paths:` filter and push that fix on the same branch (workflow files are in their own filters, so the change re-triggers the run).

### Phase 0 — Stop the Bleeding (actively exploitable)

| #   | Status | Issue                                                          | Files                                                                                                     | Closes                                                                                                                 |
| --- | ------ | -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| 0.1 | [x]    | `abvToArrayBuffer` byte-offset bug                             | `src/utils/{conversion,timingSafeEqual}.ts`, `src/cipher.ts` setAAD, `src/x509certificate.ts` string ctor | `timingSafeEqual` HIGH, all AEAD `setAAD` HIGH, x509 string-input pool-leak (newly found), conversion.ts doc hardening |
| 0.2 | [x]    | XSalsa20 keystream restart on every `update()`                 | `cpp/cipher/XSalsa20Cipher.{cpp,hpp}`                                                                     | XSalsa20 catastrophic finding                                                                                          |
| 0.3 | [x]    | DH/ECDH peer-key validation missing                            | `cpp/dh/HybridDiffieHellman.cpp`, `cpp/ecdh/HybridECDH.cpp`                                               | DH/ECDH HIGH findings                                                                                                  |
| 0.4 | [x]    | RSA Bleichenbacher oracle (PKCS#1 v1.5 distinguishable errors) | `cpp/cipher/HybridRsaCipher.cpp`, `src/utils/publicCipher.ts`                                             | RSA Cipher HIGH                                                                                                        |

### Phase 1 — Shared Foundation (root-cause helpers)

Once these helpers exist the bulk Phase 2/3 sweep just consumes them.

| #   | Status | Helper                                                                       | Closes                                                                     |
| --- | ------ | ---------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| 1.1 | [x]    | `validateUInt()` — reject NaN/Inf/negative/non-integer at JS↔C++ boundary    | ~20 findings (Hash, HMAC, KMAC, BLAKE3, all KDFs, RSA, ML-DSA, AES-CCM)    |
| 1.2 | [x]    | `secureZero()` — `OPENSSL_cleanse` / `sodium_memzero` wrapper                | XSalsa20, XChaCha20-Poly1305, all KDFs, DH/ECDH, RSA/EC/Ed/DSA DER strings |
| 1.3 | [x]    | `EVP_CIPHER_CTX` `unique_ptr` in `HybridCipher` base                         | CCMCipher, ChaCha20, ChaCha20-Poly1305 destructor leaks                    |
| 1.4 | [x]    | Replace `Record<string, any>` `getUIntOption` with typed helper              | Cross-cutting cipher options                                               |

### Phase 2 — Memory Safety Sweep

Depends on Phase 1.

- [x] Raw `new uint8_t[]` → `std::unique_ptr<uint8_t[]>` (Hash, HMAC, KMAC, BLAKE3, all KDFs, all ciphers' `update()`)
- [x] Raw `EVP_PKEY*` → smart pointers (RSA, EC, Ed, Sign/Verify, ML-DSA, ML-KEM — DSA pattern as template)
- [x] `Promise::async` raw `this` capture → `shared_from_this` (ML-DSA, ML-KEM; DH had no async sites)
- [x] `EVP_PKEY_CTX` double-free in `EVP_DigestSignInit` paths (Sign/Verify, Ed25519, ML-DSA)
- [x] Ed25519 thread-unsafe `ERR_error_string(.., NULL)` → `ERR_error_string_n`

### Phase 3 — TypeScript Boundary Validation

- [x] Cipher algorithm/key/IV length validation at TS layer
- [x] KDF parameter validation: Scrypt N power-of-2; HKDF max `255 * HashLen`; Argon2 RFC 9106 mins; PBKDF2 already done — use as template
- [x] RSA modulus min 2048 bits (currently 256)
- [x] DSA modulus min 1024 bits (currently 0)
- [x] WebCrypto `subtle`: case-insensitive `normalizeAlgorithm`; JWK `ext`/`key_ops`; `deriveBits` usage; HKDF `extractable: false`
- [x] Stream `_transform`/`_flush` error propagation via callback (Hash, HMAC, all ciphers)

### Phase 4 — Test Vector Coverage

- [x] NIST KATs: Hash (SHA family), AES-GCM/CCM/OCB, ML-DSA, ML-KEM
- [x] RFC vectors: HKDF (RFC 5869, all 7), BLAKE3 keyed_hash/derive_key, Argon2 RFC 9106 with output comparison, Scrypt RFC 7914 Test Case 4
- [x] AEAD misuse tests: `setAAD` after `update`, `getAuthTag` on decipher, `setAuthTag` on cipher, missing `setAuthTag` before decrypt
- [ ] Wrong key/IV size rejection tests (every cipher)
- [x] Fix fire-and-forget async assertions (PBKDF2, Random)
- [ ] Cross-implementation verification (Node.js ↔ RNQC for sigs/KDFs)

### Phase 5 — Cross-Cutting Audit Items (still unstarted)

- [ ] `bun audit` on all workspace packages
- [ ] Native dep CVE check (blake3, ncrypto, fastpbkdf2, OpenSSL-Universal, libsodium)
- [ ] GitHub Actions review (injection, secrets exposure)
- [ ] `.npmignore` / published-artifact review (no test fixtures, keys, configs)
- [ ] Expo plugin (`withRNQC`) code-injection review

---

### Progress Log

_Append entries as PRs land. Format: `YYYY-MM-DD — [phase.task] description (PR #)`_

- 2026-04-26 — [0.1] Fix byte-offset bugs across `timingSafeEqual`, AEAD `setAAD`, and X.509 string constructor. Harden `abvToArrayBuffer` doc to flag the zero-copy semantic. Adds 5 regression tests (3 timingSafeEqual view cases, 2 GCM sliced-AAD cases). (branch: `feat/security-audit`, PR: TBD)
  - Newly discovered while sweeping: `X509Certificate(string)` was using `Buffer.from(str).buffer` which can return a pool-backed ArrayBuffer with non-zero `byteOffset` — same class of bug as `setAAD`. Fixed in this pass.
- 2026-04-26 — [0.2] Fix XSalsa20 keystream restart on every `update()`. Replace `crypto_stream_xor` with `crypto_stream_xsalsa20_xor_ic` plus per-instance `block_counter` + 64-byte `leftover_keystream` so the keystream advances correctly across chunked update() calls. Output now uses `unique_ptr` for exception safety on the failure path. Adds 6 streaming regression tests covering block-aligned splits, mid-block splits, many-small-chunk splits, drain-to-boundary continuation, the catastrophic two-time-pad regression (identical plaintext in two updates → distinct ciphertexts), and a streaming round-trip across encrypt + decrypt instances. Independent crypto-specialist review approved correctness, exception safety, and re-init isolation. (branch: `feat/security-audit`, PR: TBD)
- 2026-04-26 — [0.3] Add explicit peer-public-key validation in `DiffieHellman::computeSecret` and `ECDH::computeSecret`. DH path calls `DH_check_pub_key` (matching ncrypto's `DHPointer::checkPublicKey`) and distinguishes TOO_SMALL / TOO_LARGE / INVALID error codes, closing the small-subgroup attack on peer pubkeys 0, 1, p-1, and p. ECDH path calls `EC_POINT_oct2point` → `EC_POINT_is_at_infinity` → `EC_POINT_is_on_curve` against the configured group, closing the invalid-curve attack (peer point on a related weaker curve). Adds 4 DH and 5 ECDH regression tests covering each rejection path plus a cross-curve attack (P-384 pubkey sent to a P-256 instance) and a bit-flipped-coordinate test. Crypto-specialist review approved both fixes; flagged that the q-less subgroup gap for caller-supplied DH primes matches Node.js behavior and is not a regression. (branch: `feat/security-audit`, PR: TBD)
- 2026-04-26 — [0.4] Close the RSA PKCS#1 v1.5 Bleichenbacher oracle. `HybridRsaCipher` now (1) enables OpenSSL 3.2+ implicit rejection (`EVP_PKEY_CTX_ctrl_str(ctx, "rsa_pkcs1_implicit_rejection", "1")`) for every PKCS#1 v1.5 decryption — corrupted ciphertexts deterministically decrypt to random-looking bytes instead of throwing — and (2) routes every decrypt-failure path in `decrypt`, `privateDecrypt`, and `publicDecrypt` (verify-recover) through a single `throwOpaqueDecryptFailure()` helper that emits the same `"RSA decryption failed"` message and clears the OpenSSL error stack so the underlying reason never reaches the caller. The TS wrapper drops the `: ${error.message}` interpolation in `privateDecrypt`/`publicDecrypt`. If the OpenSSL build does not support the implicit-rejection knob (BoringSSL or pre-3.2) we hard-fail PKCS#1 v1.5 decryption with a build-config error rather than silently leaving the timing-side oracle open — matches Node.js's `crypto_cipher.cc` policy. Adds 5 regression tests: corrupted PKCS#1 v1.5 doesn't throw, the implicit-rejection output is deterministic per (key, ciphertext) and distinct across different ciphertexts, OAEP/wrong-label errors are opaque (no "openssl/padding/oaep/label" terms in the message), OAEP and PKCS#1 wrong-padding errors are equivalent, and `publicDecrypt` errors are opaque. Crypto-specialist review confirmed the fix is closer to Node-compat than the previous behavior and approved the hard-fail fallback. (branch: `feat/security-audit`, PR: TBD)
- 2026-04-26 — [1.1–1.4] Phase 1 shared foundation: add `validateUInt<T>()`, `secureZero()` overloads, `EVP_CIPHER_CTX` RAII in the cipher base, and a typed `getUIntOption` helper to `cpp/utils/QuickCryptoUtils.hpp` and `src/utils/cipher.ts`. Sweeps the cipher base + GCM/CCM/ChaCha20/ChaCha20-Poly1305/OCB/XSalsa20-Poly1305 to consume the new RAII context. Adds Argon2/cipher boundary tests. (PR #983)
- 2026-04-26 — [2.1–2.5] Phase 2 memory safety sweep across 24 C++ files (+327/−480 lines net). Item 2.1: convert raw `new uint8_t[]` to `std::unique_ptr<uint8_t[]>` + `release()` into `NativeArrayBuffer` in Hash, HMAC, KMAC, BLAKE3, PBKDF2, Scrypt, HKDF, the cipher base `update()`, ChaCha20/ChaCha20-Poly1305/XChaCha20-Poly1305/XSalsa20-Poly1305, CCM `final()`, RSA-cipher decrypt sentinels, Ed25519 (6 sites), ML-DSA (3 sites), and ML-KEM (4 sites). Item 2.2: replace raw `EVP_PKEY*` ownership with `std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>` in RSA, EC, and Ed25519 keypair classes (DSA pattern as template); `Ed25519::importPublicKey`/`importPrivateKey` now return owning `EVP_PKEY_ptr` and use `EVP_PKEY_up_ref` for the borrow-the-instance-key path, closing the audit-flagged leak. Item 2.3: replace `Promise<…>::async([this, …])` with `auto self = this->shared_cast<…>(); [self, …]` in ML-DSA (3 sites) and ML-KEM (3 sites); DH had no async sites despite the audit listing. Item 2.4: eliminate the unnecessary `EVP_PKEY_CTX_new_from_name` pre-creation in Sign/Verify handles, ML-DSA, and Ed25519 — pass `nullptr` for the `EVP_PKEY_CTX**` arg and let `EVP_DigestSignInit` allocate from the key's keymgmt (matches `ncrypto::EVPMDCtxPointer::signInit`). Crypto-specialist review confirmed the old code was actually *leaking* the pre-allocated PKEY_CTX (OpenSSL silently overwrote the pointer on success), so this fix closes both the audited double-free *and* an unreported leak. Wraps EVP_MD_CTX/EVP_PKEY_CTX in local `unique_ptr` aliases so all manual error-path frees collapse. Item 2.5: replace Ed25519's two `ERR_error_string(ERR_get_error(), NULL)` calls with the shared `getOpenSSLError()` helper. Defense-in-depth: `secureZero` added on Scrypt/HKDF error paths and on Ed25519/ML-DSA/ML-KEM `getPrivateKey` BIO buffers. Crypto-specialist approved all four substantive concerns (algorithm selection unchanged, refcount semantics correct, BIO secure-zero is safe redundancy with `BUF_MEM_free`'s `OPENSSL_clear_free`, `release()` + `make_shared` window matches Nitro's own `ArrayBuffer::wrap`). (PR #984)
- 2026-04-27 — [CI] Fix the 6 GitHub Actions warnings surfaced on PR #984's runs: opt all workflows into Node.js 24 via `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` (silences the deprecation warning for `setup-java@v4`, `upload/download-artifact@v4`, `setup-android@v3`, `peter-evans/*`, `McCzarny/*`, `reviewdog/*`); bump `actions/checkout@v4` and `actions/setup-node@v4` to `@v5` everywhere; replace the `${{ github.run_id }}` Gradle/node_modules/AVD cache keys with `hashFiles(...)`-based keys (and a stable `avd-pixel7pro-34-x86_64-v1` for the AVD) to fix the "another job may be creating this cache" save failures; bump library AGP `classpath` 8.7.3 → 8.12.2 (matches Nitro) and disable the `AndroidGradlePluginVersion` / `GradleDependency` lint checks since AGP 9.x requires Gradle 9 + JDK 21 which RN 0.81's toolchain can't supply. (branch: `feat/security-audit-phase-3`, PR: TBD)
- 2026-04-27 — [3.1] Pre-validate cipher algorithm, key, and IV byte-lengths at the JS↔C++ boundary. `validateCipherParams()` in `src/cipher.ts` rejects empty / non-string `cipherType` with `TypeError`, splits the existing `getCipherInfo()` probe into name-only / name+keyLen / name+ivLen calls so the thrown error names exactly which parameter is wrong, hard-codes (key=32, iv=24) for libsodium ciphers OpenSSL doesn't see (xsalsa20, xsalsa20-poly1305, xchacha20-poly1305), and rejects empty IV when the cipher requires one and non-empty IV when it doesn't. Wired into `Cipheriv` / `Decipheriv` constructors and the `xsalsa20()` shim. 11 regression tests covering empty/unknown name, too-short / too-long / empty key for AES-CBC, wrong IV for CBC and CCM, accepted variable IV for GCM, decipher mirror, and wrong-key + wrong-nonce for xsalsa20. (branch: `feat/security-audit-phase-3`, PR: TBD)
- 2026-04-27 — [3.2] KDF parameter validation at the TS layer. **Scrypt**: `validateScryptParams()` enforces RFC 7914 §6 — N power-of-2 > 1, r/p positive integers, r * p < 2^30, and 128 * r * N ≤ maxmem. **HKDF**: `validateHkdfKeylen()` enforces RFC 5869 §2.3 (L ≤ 255 * HashLen) using a static `HKDF_HASH_BYTES` table covering sha1/224/256/384/512, sha3-256/384/512, ripemd160. Wired into hkdf, hkdfSync, and the WebCrypto `hkdfDeriveBits`. **Argon2**: `validateArgon2Params()` enforces RFC 9106 §3.1 minimums — 1 ≤ p ≤ 2^24-1, T ≥ 4, m ≥ 8 * p (KiB), t ≥ 1, salt 8..2^32-1 bytes, version ∈ {0x10, 0x13}. Async paths surface the new errors via callback. Existing argon2 tests that asserted the C++ `validateUInt`-style messages are refreshed to match the new RFC 9106 wording (the JS-side check now fires first). 8 scrypt + 5 HKDF + 7 Argon2 RFC 9106 minimum-bound regressions. (branch: `feat/security-audit-phase-3`, PR: TBD)
- 2026-04-27 — [3.3] RSA modulus minimum lifted from 256 → 2048 bits (NIST SP 800-131A Rev. 2; RFC 8017). `RSA_MIN_MODULUS_LENGTH` is shared between the WebCrypto (`rsa_generateKeyPair`) and Node-API (`rsa_prepareKeyGenParams`) entry points. WebCrypto path stays a `DOMException` so JOSE callers see the same exception type. Bumped 12 in-repo test fixtures from `modulusLength: 1024` → `2048` across `subtle/generateKey.ts` and `subtle/import_export.ts`, and added explicit modulusLength=1024 rejection coverage at both boundaries. (branch: `feat/security-audit-phase-3`, PR: TBD)
- 2026-04-27 — [3.4] DSA modulus minimum lifted from `> 0` → 1024 bits (FIPS 186-4 §4.2 sanctions only L ∈ {1024, 2048, 3072}). 1024 retained as the floor (rather than 2048) so legacy interop callers have a fallback. The `Invalid or missing modulusLength` generic Error becomes a `RangeError: DSA modulusLength must be at least 1024 bits (got N)`. 2 regression tests (modulusLength 512 and 0). (branch: `feat/security-audit-phase-3`, PR: TBD)
- 2026-04-27 — [3.5] WebCrypto `subtle` hardening on four under-enforced edges. (a) `normalizeAlgorithm` performs case-insensitive lookup against a lazy `SUPPORTED_ALGORITHMS` lower→canonical map, so `'aes-gcm'` → `'AES-GCM'` instead of bypassing the supported-set comparisons. (b) New `validateJwkExtAndKeyOps()` helper rejects `jwk.ext === false` with `extractable === true` and rejects when `jwk.key_ops` is present but does not cover every requested usage; wired into KMAC, RSA, HMAC, AES, and Ed/CFRG JWK import branches. (c) `subtle.deriveBits` now strictly requires the literal `deriveBits` usage (was `deriveBits || deriveKey`), per spec step 11. (d) `hkdfImportKey` throws `SyntaxError` when `extractable: true` is requested and forces `extractable: false` on the resulting `CryptoKey`, matching §28.7.6. 6 regression tests (lowercase digest, deriveBits-without-deriveBits, HKDF non-extractable enforcement + force-false invariant, AES JWK ext/key_ops triad). (branch: `feat/security-audit-phase-3`, PR: TBD)
- 2026-04-27 — [3.6] Stream `_transform` / `_flush` error propagation in Hash, Hmac, and Cipher. Each wrapped body is now a try/catch that forwards the thrown `Error` through the stream callback so it emits as a regular `'error'` event and the Transform always sees the callback exactly once on every code path. Callback parameter type widened from `() => void` to `(err?: Error | null) => void`. 6 regression tests covering Hash/Hmac update/digest after digest() and Cipher update after final() / Decipher final with a tampered AES-GCM tag. (branch: `feat/security-audit-phase-3`, PR: TBD)
- 2026-04-27 — [Phase 3 review polish] Address review follow-ups across the Phase 3 work. **(2)** `validateCipherParams` fast-path: cache the `getCipherInfo(name)` result and short-circuit when `(key, iv)` match the cipher's defaults, dropping the round-trip count from 3→1 for the common case (AES-CBC, AES-GCM with default 12-byte IV, ECB, etc.) while preserving the per-parameter error messages on the failure path. **(3)** Drop the `Number.isFinite(keyByteLength)` clause — `ArrayBuffer.byteLength` is always a non-negative integer, so the only meaningful guard is `=== 0`. **(4)** `validateHkdfKeylen` now throws `TypeError: Unsupported HKDF digest: <name>` for digests not in `HKDF_HASH_BYTES` (e.g. SHAKE128 — XOFs aren't valid HKDF inputs since HKDF builds on HMAC), instead of silently skipping the ceiling check. **(5)** `validateArgon2Params` returns the resolved `nonceAB` so both the validator and the native call share a single `binaryLikeToArrayBuffer(params.nonce)` round-trip. **(6)** Type the lazy canonical-name map as `Map<string, AnyAlgorithm>` so the cast lives at insertion (where the contract is enforced by `SUPPORTED_ALGORITHMS`) rather than at every `normalizeAlgorithm` lookup. **(7)** Re-express the Phase 3.6 stream tests through the public stream API (`h.write()` / `h.end()`) and assert on `'error'` events, removing the `(stream as any)._transform/_flush(...)` casts. Adds 1 new HKDF regression for the unknown-digest throw. (branch: `feat/security-audit-phase-3`, PR: TBD)
- 2026-04-27 — [4.5] Fix fire-and-forget async assertions in the PBKDF2 and Random suites. Pre-fix, every `crypto.pbkdf2(..., cb)` and `crypto.randomFill(..., cb)` test ran assertions inside the callback after the test function had already resolved — a wrong digest, a non-null `err`, or a wrong byte length silently produced an unhandled rejection rather than a test failure. Each affected test now wraps the callback in a `new Promise<void>((resolve, reject) => …)` and returns it so the runner's `await test()` actually observes the assertion outcome. Touched: PBKDF2 `RFC 6070 testFn`, the `handles buffers` mixed sync/async test, and the per-algorithm fixture-driven `async w/ …` loop (≈42 generated tests). Random suite: `simple test 5/6/7/8`, `randomFill - deepStringEqual - Buffer/Uint8Array`, the `randomFill (async) - view over larger buffer …` regression test, the `randomBytes`/`pseudoRandomBytes` length matrix (16 generated tests), and the three `randomInt - Asynchronous API / positive range / negative range` 100-iteration soak tests. Each `randomInt` test now uses a single `settled` flag so the first-failing assertion rejects exactly once even when 100 callbacks are in flight. Adds 2 negative regression tests (one per suite) that purposely assert `expect(...).to.equal(<wrong>)` inside a callback — verifying via `assertThrowsAsync` that the new wrapper actually surfaces the failure. Smoke-test cases that have no assertions (e.g. `randomInt 1`, `randomFill int16` — bodies that exist purely to verify the call doesn't throw synchronously) are intentionally left as-is to keep this commit scoped to the fire-and-forget *assertion* class; converting them changes "no synchronous throw" semantics into "callback completes" semantics, a separate concern. (branch: `feat/security-audit-phase-4`, PR: TBD)
- 2026-04-27 — [4.2] Add RFC test-vector coverage. **HKDF**: expand from RFC 5869 Case 1 only to all 7 cases (§A.1–A.7) — covering both SHA-256 (Cases 1–3) and SHA-1 (Cases 4–7), basic + long inputs, zero-length salt+info, and Case 7's "salt not provided" path. Also adds a SHA-1 WebCrypto `subtle.deriveBits` test that the existing Node-API loop doesn't exercise. **Argon2**: add output-byte comparison against the canonical RFC 9106 §5 KAT tags for argon2d / argon2i / argon2id (the existing tests only checked `result.length === 32`, accepting any 32 random bytes). Pulls the three tags from Node.js's `test-webcrypto-derivebits-argon2.js` (Node's vectors are taken from RFC 9106 §5.1/§5.2/§5.3). Pre-existing input set `RFC_PARAMS` already had the §5 (P, S, K, X, t, m, p, T, v=0x13) tuple; the version is now passed explicitly to argon2Sync/argon2 so a future binding-default change can't silently break the KAT. **Scrypt**: add RFC 7914 §11 Test Case 4 (P="pleaseletmein", S="SodiumChloride", N=2^20, r=8, p=1, dkLen=64) with `maxmem: 1.5 GiB`. Lives in its own opt-in suite `scrypt-tc4-slow` because the working set is ~1.07 GiB and would OOM on Android emulators / slow CI substantially — Node.js's parallel scrypt test omits this vector for the same reason. Sync + async variants. **BLAKE3**: add `BLAKE3_KAT_CASES` array with the first-32-bytes-of-extended-output for keyed_hash and derive_key modes for input_len ∈ {0, 1, 8, 64}, sourced verbatim from `packages/react-native-quick-crypto/deps/blake3/test_vectors/test_vectors.json`. Pre-existing tests checked that keyed mode produced *something different* from unkeyed but never pinned to the published BLAKE3 KAT bytes. Module-load assertion that `BLAKE3_KAT_KEY.length === 32` so future Unicode contamination of the source string can't silently shift every expected output. Crypto-specialist independently verified all 7 HKDF tuples, all 3 Argon2 tags, the Scrypt TC4 expected output, and all 8 BLAKE3 (mode, input_len) entries against their RFC / source-of-truth values. (branch: `feat/security-audit-phase-4`, PR: TBD)
- 2026-04-27 — [4.1] NIST KAT coverage. **Hash (SHA family)**: add 33 tests pinning empty-string + "abc" outputs for sha1, sha224, sha256, sha384, sha512, sha512-224, sha512-256, sha3-224, sha3-256, sha3-384, sha3-512 against FIPS 180-4 Appendix C / FIPS 202 §B.1 published values, plus the FIPS 180-4 §B.3/§B.5 long-input ("a" × 1,000,000) vectors for SHA-256 and SHA-512 to exercise the multi-chunk path. The empty-string + "abc" outputs are also driven through the `hash()` one-shot wrapper so both the streaming and one-shot APIs are pinned. **AES-GCM/CCM/OCB**: add an `AEAD_KATS` array with NIST GCM Test Cases 2/3/4 (Joux/McGrew "GCM" Test Vectors), NIST SP 800-38C CCM Examples C.1 (Tlen=4 B), C.2 (Tlen=6 B), C.3 (Tlen=8 B), and RFC 7253 §A AES-OCB vectors for empty + (8B P, 8B AAD). Each KAT runs both `encrypt` (assert ciphertext + tag bytes) and `decrypt` (assert plaintext recovers from given C+T). Until now the cipher suite only verified round-trip identity over `getCiphers()` output, which catches wiring bugs but doesn't pin any cipher's bit-exact output against another implementation. **ML-DSA**: add cross-variant rejection (44-sig under 65-pub must fail), tampered-message rejection, and full PKCS8/SPKI export → import → sign+verify round-trip per variant — verifying the imported signature against both the imported public key and the originally-generated public key. **ML-KEM**: add FIPS 203 implicit-rejection tests (tampered ciphertext returns 32 deterministic-but-different bytes, never throws; wrong private key likewise produces different deterministic bytes), plus cross-variant size-rejection (768 ciphertext into 512 priv must throw — size validation runs before any KEM op). OpenSSL doesn't expose seeded ML-DSA/ML-KEM keygen so we can't anchor to the FIPS 204/203 KAT outputs deterministically; these tests pin the FIPS-mandated *properties* observable at a black-box level. Crypto-specialist independently verified the FIPS 180-4/202 hash digests and the NIST AES-GCM/CCM/OCB AEAD outputs. Two transcription errors were caught and corrected before commit (SHA-512/224 empty-string output had a wrong digit count + value; the OCB §A "8B P + 8B AAD" entry had been written against the wrong nonce N=...221103 with bogus C/T values, replaced with the actual §A N=...221101 vector C=`6820b3657b6f615a` T=`5725bda0d3b4eb3a257c9af1f8f03009`). (branch: `feat/security-audit-phase-4`, PR: TBD)
- 2026-04-27 — [4.3] AEAD misuse-resistance tests. Each AEAD spec mandates a strict ordering of API calls; implementations that silently accept misordered calls open up real attacks (e.g. `setAAD` after `update` lets an attacker truncate AAD bytes the application thought were authenticated). Adds 4 tests per cipher across `aes-128-gcm`, `aes-256-gcm`, `aes-128-ccm`, `aes-128-ocb`, `chacha20-poly1305` (20 tests total): (1) `setAAD` after `update` must throw, (2) `setAuthTag` on a `Cipher` instance must throw — only Decipher consumes tags, (3) `getAuthTag` on a `Decipher` instance must throw — only Cipher produces tags, (4) `decipher.final()` without first calling `setAuthTag` must throw — otherwise the call accepts unauthenticated ciphertext, defeating the AEAD guarantee. Pinning these matches Node's crypto-module behavior. (branch: `feat/security-audit-phase-4`, PR: TBD)
