# Version 1.0.0 - Post-Release Enhancements

Items deferred from the 1.0.0 release for future consideration.

## Known Limitations

### 1. `generateKeyPairSync()` for RSA/EC

**Status:** Throws descriptive error; async version works

**Current Behavior:**
```typescript
generateKeyPairSync('rsa', options); // throws "Sync key generation for RSA/EC not yet implemented"
generateKeyPair('rsa', options, callback); // works
```

**Implementation Notes:**
- Async version uses WebCrypto-style async APIs internally
- True sync requires adding synchronous C++ methods to `HybridRsaKeyPair` and `HybridEcKeyPair`
- Pattern exists in Ed25519/X25519 which have working sync variants
- Work: Add sync variants to RSA/EC Nitro specs, implement in C++, wire up TypeScript

**Effort:** Medium-High (~2-3 hours)

---

### 2. `publicEncrypt`/`publicDecrypt` - PKCS1 Padding

**Status:** Only OAEP padding supported

**Current Behavior:**
```typescript
publicEncrypt({ key, padding: constants.RSA_PKCS1_OAEP_PADDING }, buffer); // works
publicEncrypt({ key, padding: constants.RSA_PKCS1_PADDING }, buffer); // not implemented
```

**Implementation Notes:**
- `HybridRsaCipher` already exists with OAEP support
- PKCS1 padding is simpler than OAEP (no hash algorithm, no label)
- Add padding mode parameter and handle `RSA_PKCS1_PADDING` in C++
- OpenSSL EVP APIs support it directly

**Effort:** Low-Medium (~1-2 hours)

---

### 3. `privateEncrypt`/`privateDecrypt`

**Status:** Not implemented (0.x didn't have these either)

**Description:**
- Inverse operations of publicEncrypt/publicDecrypt
- Sign with private key, verify/decrypt with public key
- Used for raw RSA signatures

**Implementation Notes:**
- Similar to publicEncrypt/publicDecrypt but swap key roles
- Can reuse much of `HybridRsaCipher` infrastructure
- OpenSSL: `EVP_PKEY_sign`/`EVP_PKEY_verify` or raw RSA operations

**Effort:** Low-Medium (~1-2 hours)

---

## Summary

| Feature | Effort | Priority |
|---------|--------|----------|
| `generateKeyPairSync` RSA/EC | Medium-High | Low (async works) |
| PKCS1 padding | Low-Medium | Medium |
| `privateEncrypt`/`privateDecrypt` | Low-Medium | Low (0.x parity) |

**Total estimated effort:** 4-7 hours

These can be addressed based on user demand post-1.0.0 release.
