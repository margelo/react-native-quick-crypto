# Quick Implementation Wins

Items identified during the implementation-coverage audit (#907) that should be
straightforward to implement.

## crypto.hash() oneshot function
- Node.js v21.7.0+ `crypto.hash(algorithm, data[, outputEncoding])`
- Simply wraps createHash/update/digest in one call
- Trivial to implement — just a convenience function
- Reference: `crypto.createHash(algorithm).update(data).digest(outputEncoding)`

## subtle.deriveKey with ECDH
- `subtle.deriveBits` already supports ECDH via `ecDeriveBits()`
- `subtle.deriveKey` is missing the ECDH case in its switch statement
- Fix: add `case 'ECDH':` to the deriveKey switch that calls deriveBits (same pattern as X25519/X448)

## crypto.getCurves()
- Similar to existing `getCiphers()` and `getHashes()`
- Returns list of supported EC curve names
- OpenSSL has APIs to enumerate curves

## Ed25519/Ed448 JWK export/import
- spki/pkcs8/raw formats already work
- JWK is the remaining gap
- Node.js and WebCrypto both support JWK for Ed25519/Ed448
- Closes #653 (subtle.importKey with Ed25519)

## KeyObject.equals()
- Compare two KeyObjects for equality
- Should be straightforward with exported key comparison

## KeyObject.symmetricKeySize
- Return the size of a symmetric key in bytes
- Simple property accessor

## createDiffieHellmanGroup alias
- Node.js exports `createDiffieHellmanGroup` as an alias for `getDiffieHellman`
- `getDiffieHellman` already exists and works
- Just add a re-export: `export { getDiffieHellman as createDiffieHellmanGroup }`

## diffieHellman.verifyError
- DiffieHellman class is fully implemented except this property
- Returns verification errors from DH parameter checking
