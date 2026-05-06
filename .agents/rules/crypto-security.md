# Crypto Security Rules

Always on for crypto work.

## Blocking

- Match specs exactly: WebCrypto, Node.js, RFCs.
- Validate against authoritative test vectors.
- Handle edge cases and boundaries.
- Use constant-time operations for secret/authentication comparisons.
- Use `CRYPTO_memcmp()` for tags/MACs; never `memcmp()`.
- Use `RAND_bytes()` for cryptographic randomness; never `rand()`, `srand()`, or time seeds.
- Check `RAND_bytes()` return values.
- Prefer AEAD: AES-GCM or ChaCha20-Poly1305.
- Verify authentication before exposing plaintext.
- Never expose partial plaintext on auth failure.

## Strict

- Never reuse IV/nonce with the same key.
- Use correct nonce lengths, especially 12 bytes for GCM.
- Generate random nonces with `RAND_bytes()` unless the spec requires otherwise.
- Reject insufficient key sizes.
- Minimums: AES 128-bit, RSA 2048-bit, ECC P-256-class, HMAC matching hash output.
- PBKDF2 minimum: 600,000 iterations; random unique salt >= 16 bytes; SHA-256 or better.
- Never put key material in errors, logs, exceptions, or debug output.
- Use generic auth/decryption errors; no padding or tag mismatch detail.

## Algorithms

Approved:

- AES-GCM, ChaCha20-Poly1305.
- SHA-256/384/512.
- HMAC-SHA256 or better.
- RSA-OAEP/PSS.
- ECDSA/ECDH on safe curves.
- PBKDF2, Argon2, scrypt.

Forbidden:

- MD5.
- SHA-1 for signatures.
- DES/3DES.
- RC4.
- AES-ECB.
- AES-CBC without HMAC.

## Validation

- Use NIST, RFC, Node.js, and WebCrypto test vectors.
- Consider timing/cache side channels; at minimum, make secret comparisons timing-safe.
