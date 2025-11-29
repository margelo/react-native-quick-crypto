# Version 1.0.0 TODO - Parity with 0.x

This document tracks what needs to be implemented in the `main` branch to achieve full parity with the `0.x` branch before releasing version 1.0.0.

**Last Updated:** 2025-11-29

## Status Legend

- ✅ **Implemented** - Feature is complete (both TS and C++/Nitro)
- 🚧 **Partial** - Feature exists but incomplete or commented out
- ❌ **Missing** - Feature needs implementation from scratch
- 📝 **Docs Only** - Feature exists but documentation needs updating

---

## Critical Findings Summary

### Documentation Issues (No Code Needed)

These are already implemented but incorrectly marked in `docs/implementation-coverage.md`:

1. 📝 **`keyObject.type`** 
   - Status: ✅ Implemented in `src/keys/classes.ts:111`
   - Action: Update docs from ❌ to ✅

2. 📝 **`crypto.createSecretKey`**
   - Status: ✅ Fully implemented (TS + C++/Nitro)
   - TypeScript: `src/keys/index.ts:20-23`
   - C++ Native: `cpp/keys/HybridKeyObjectHandle.cpp:352-354`
   - Action: Update docs from ❌ to ✅

---

## Missing Features (Implementation Required)

### 1. Sign/Verify Classes ❌

**Node.js Classic API**

**What's Missing:**
- `crypto.createSign(algorithm[, options])`
- `crypto.createVerify(algorithm[, options])`
- `Sign` class with methods:
  - `sign.update(data[, inputEncoding])`
  - `sign.sign(privateKey[, outputEncoding])`
- `Verify` class with methods:
  - `verify.update(data[, inputEncoding])`
  - `verify.verify(object, signature[, signatureEncoding])`

**Evidence:**
- Code commented out in `src/keys/index.ts:7`
- Classes not found in codebase

**Reference:**
- 0.x had this: ✅
- Node.js reference: `$REPOS/node/deps/ncrypto`

**Implementation Notes:**
- WebCrypto equivalents (`subtle.sign`/`subtle.verify`) are partially implemented
- Classic Node API provides streaming interface vs WebCrypto's Promise-based
- Need C++ integration with OpenSSL EVP_DigestSign/EVP_DigestVerify

**Priority:** HIGH - Common API in Node.js crypto

---

### 2. createPrivateKey / createPublicKey ❌

**Node.js Classic API**

**What's Missing:**
- `crypto.createPrivateKey(key)`
- `crypto.createPublicKey(key)`

**Evidence:**
- Both commented out in `src/keys/index.ts:26-27`
- `createSecretKey` is implemented, so pattern exists

**Reference:**
- 0.x had this: ✅
- Node.js reference: `$REPOS/node/deps/ncrypto`

**Implementation Notes:**
- C++ infrastructure exists in `KeyObjectHandle::init()` for public/private keys
- TypeScript wrapper needed similar to `createSecretKey` pattern
- Should support multiple input formats (PEM, DER, JWK, KeyObject)

**Priority:** HIGH - Fundamental key management API

---

### 3. crypto.constants ❌

**Node.js Classic API**

**What's Missing:**
- `crypto.constants` object with OpenSSL constants

**Evidence:**
- No `constants` export found in `src/` directory
- Grep for `export.*constants` returned no results

**Reference:**
- 0.x had this: ✅
- Node.js reference: `$REPOS/node/lib/crypto.js`

**Implementation Notes:**
- Should include constants for:
  - RSA padding modes (RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING, etc.)
  - Point conversion forms
  - OpenSSL engine constants
  - Default DH groups
- Most are mappings to OpenSSL constants from `openssl/rsa.h`, etc.

**Priority:** MEDIUM - Required for advanced crypto operations

---

### 4. publicEncrypt / publicDecrypt ❌

**Node.js Classic API**

**What's Missing:**
- `crypto.publicEncrypt(key, buffer)`
- `crypto.publicDecrypt(key, buffer)`
- Note: `privateEncrypt`/`privateDecrypt` also missing (0.x didn't have these either)

**Evidence:**
- Grep returned no matches in `src/`
- 0.x had `publicEncrypt`/`publicDecrypt`: ✅

**Reference:**
- 0.x implementation
- Node.js reference: `$REPOS/node/deps/ncrypto`

**Implementation Notes:**
- C++ implementation would use `EVP_PKEY_encrypt`/`EVP_PKEY_decrypt`
- WebCrypto equivalent (`subtle.encrypt` with RSA-OAEP) is implemented
- Classic API provides more control over padding modes
- Should support various key formats and padding options

**Priority:** MEDIUM - Less common than Sign/Verify but still used

---

### 5. generateKeyPair for RSA/EC ❌

**Node.js Classic API**

**What's Missing:**
- `crypto.generateKeyPair('rsa', options, callback)`
- `crypto.generateKeyPair('rsa-pss', options, callback)`
- `crypto.generateKeyPair('ec', options, callback)`
- `crypto.generateKeyPairSync('rsa', options)`
- `crypto.generateKeyPairSync('rsa-pss', options)`
- `crypto.generateKeyPairSync('ec', options)`

**Evidence:**
- `src/keys/generateKeyPair.ts:123-138` only supports: `ed25519`, `ed448`, `x25519`, `x448`
- Switch statement falls through to error for all other types

**Reference:**
- 0.x had RSA and EC: ✅
- Node.js reference: `$REPOS/node/deps/ncrypto`

**Implementation Notes:**
- WebCrypto `subtle.generateKey` for RSA/EC/ECDH is implemented
- C++ helpers exist: `rsa_generateKeyPair()` in `src/rsa.ts:59`, `ec_generateKeyPair()` in `src/ec.ts:446`
- Need to wire these into classic `generateKeyPair` API
- Key encoding/format conversion already exists in `parseKeyPairEncoding()`

**Priority:** HIGH - Common key generation patterns

---

### 6. generateKey / generateKeySync for AES ❌

**Node.js Classic API**

**What's Missing:**
- `crypto.generateKey('aes', { length: 128|192|256 }, callback)`
- `crypto.generateKeySync('aes', { length: 128|192|256 })`
- `crypto.generateKey('hmac', options, callback)` (both branches missing)
- `crypto.generateKeySync('hmac', options)` (both branches missing)

**Evidence:**
- No exports for `generateKey` or `generateKeySync` found
- Grepped for `export.*function generateKey[^P]` - no results

**Reference:**
- 0.x had AES: ✅ (HMAC was missing in both)
- Node.js reference: `$REPOS/node/deps/ncrypto`

**Implementation Notes:**
- WebCrypto `subtle.generateKey` for AES is implemented (`aesGenerateKey` exists)
- Need classic Node API wrapper that calls crypto.randomBytes
- Return should be `KeyObject` (SecretKeyObject) not `CryptoKey`
- Simpler than asymmetric key generation

**Priority:** MEDIUM - AES key generation often done manually with randomBytes

---

### 7. subtle.generateKey for Ed25519 ❌

**WebCrypto API**

**What's Missing:**
- `subtle.generateKey({ name: 'Ed25519' }, extractable, keyUsages)`

**Evidence:**
- `src/subtle.ts:967-1013` shows `generateKey()` implementation
- Switch statement handles: RSA variants, ECDSA, ECDH, AES variants
- Ed25519 not in the list (falls through to error)

**Reference:**
- 0.x had this: ✅
- WebCrypto spec: Ed25519 is standardized
- Node.js reference: `$REPOS/node/deps/ncrypto`

**Implementation Notes:**
- Classic `generateKeyPair('ed25519')` IS implemented in `src/ed.ts:171`
- Need to expose this through WebCrypto `subtle.generateKey` interface
- Should return `CryptoKeyPair` with Ed25519 algorithm
- Ed448 also missing (and also supported in classic API)

**Priority:** MEDIUM - Modern signing algorithm, WebCrypto standard

---

## Implementation Priority Order

### Phase 1: High Priority (Core APIs)
1. ✅ **createPrivateKey / createPublicKey** - Fundamental for key management
2. ✅ **Sign/Verify classes** - Common Node.js pattern
3. ✅ **generateKeyPair for RSA/EC** - Common key generation

### Phase 2: Medium Priority (Completeness)
4. ✅ **publicEncrypt / publicDecrypt** - RSA encryption operations
5. ✅ **crypto.constants** - Required for advanced usage
6. ✅ **subtle.generateKey for Ed25519/Ed448** - Modern WebCrypto standard
7. ✅ **generateKey/generateKeySync for AES** - Symmetric key generation

### Phase 3: Documentation
8. 📝 Update `docs/implementation-coverage.md` with correct status

---

## Testing Checklist

For each feature implemented, ensure:

- [ ] TypeScript implementation with proper types
- [ ] C++/Nitro native implementation if needed
- [ ] Test vectors from NIST/RFC/Node.js
- [ ] WebCrypto compliance (for subtle.* APIs)
- [ ] Node.js API compatibility (for crypto.* APIs)
- [ ] Memory safety (RAII, smart pointers, no leaks)
- [ ] Security properties (constant-time where needed, secure RNG)
- [ ] Error handling (proper OpenSSL error propagation)
- [ ] Example app tests pass
- [ ] Documentation updated

---

## Architecture Reference

### API Priority Order (from CLAUDE.md)
When implementing, prefer in this order:
1. **WebCrypto API** - Modern standard, best for `subtle.*` methods
2. **Node.js Implementation** - Use `$REPOS/node/deps/ncrypto` as reference
3. **RNQC 0.x** - Legacy reference at `$REPOS/rnqc/0.x` (OpenSSL 1.1.1, deprecated patterns)

### Tech Stack
- **TypeScript** (strict, no `any`)
- **C++20+** (smart pointers, RAII)
- **OpenSSL 3.3+** (EVP APIs only, no deprecated)
- **Nitro Modules** (native bridging)

### Code Philosophy
- Minimize code rather than add more
- Prefer iteration and modularization over duplication
- No comments unless code is sufficiently complex
- Code should be self-documenting

---

## How to Use This Document

### For Implementation
1. Pick a feature from the priority order
2. Check the "What's Missing" and "Evidence" sections
3. Review "Reference" for where to find implementation details
4. Follow "Implementation Notes" for architecture guidance
5. Run through "Testing Checklist" before marking complete

### For Progress Tracking
- Update status emoji when work begins (❌ → 🚧)
- Mark complete when tests pass (🚧 → ✅)
- Add notes/blockers in the feature section
- Update "Last Updated" date at top

### For Release Planning
- Count remaining ❌ and 🚧 items
- Estimate based on similar completed features
- Block 1.0.0 release until all ❌ → ✅

---

## Notes

### createSecretKey Discovery
The `createSecretKey` function is **fully implemented**:
- TypeScript wrapper: `src/keys/index.ts:20-23`
- C++ native support: `cpp/keys/HybridKeyObjectHandle.cpp:352-354`
- Uses `KeyObjectData::CreateSecret(ab)` which handles the ArrayBuffer
- This serves as the template for implementing `createPrivateKey`/`createPublicKey`

### Sign/Verify Pattern
While Sign/Verify classes are missing, there are existing patterns:
- WebCrypto `subtle.sign`/`subtle.verify` are partially implemented
- C++ signing infrastructure exists via `ecdsaSignVerify` and similar
- Need to create streaming/updateable interface vs Promise-based

### KeyObject Infrastructure
The C++ `KeyObjectHandle` class is robust and handles:
- Secret keys (symmetric)
- Public keys (asymmetric)
- Private keys (asymmetric)
- Multiple formats: raw, DER, PEM, JWK
- Special curves: X25519, X448, Ed25519, Ed448, EC

This means most missing features are TypeScript wrappers around existing C++ functionality.

---

**For questions or updates to this document, reference the conversation that generated it or update directly based on implementation progress.**
