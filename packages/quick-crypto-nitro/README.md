# Quick Crypto for standalone Nitro

This package exposes incremental, fixed-length OpenSSL hashes to a standalone Nitro v1 runtime on iOS and Android. It shares the digest operations used by `react-native-quick-crypto`. The current API is `createHash(algorithm)`, `update(string | ArrayBufferView, inputEncoding?)`, and `digest(encoding?)`. Calling `digest()` returns a Buffer and finalizes that hash instance.

```ts
import { createHash } from 'quick-crypto-nitro';

const hash = createHash('sha256');
hash.update('abc');
const hex = hash.digest('hex');
```

When working from a checkout, run `bash scripts/prepare-sources.sh` and `bash scripts/prepare-openssl-apple.sh` in this directory before building a native app. The package tarball includes those headers.
