# Implementation Coverage
This document attempts to describe the implementation status of Crypto APIs/Interfaces from Node.js in the `react-native-quick-crypto` library.

# `Crypto`
> TODO

# `SubtleCrypto`

> Note: A lot of isomorphic packages check the availability of `crypto.subtle` and use it instead of `crypto`. Until `crypto.subtle` is feature-complete, you might want to set it to `undefined` so that `crypto` gets used instead for transitive dependencies.

## `encrypt`
| Algorithm  | Status |
| ---------  | :----: |
| `RSA-OAEP` |  |
| `AES-CTR`  |  |
| `AES-CBC`  |  |
| `AES-GCM`  |  |

## `decrypt`
| Algorithm  | Status |
| ---------  | :----: |
| `RSA-OAEP` |  |
| `AES-CTR`  |  |
| `AES-CBC`  |  |
| `AES-GCM`  |  |

## `sign`
| Algorithm           | Status |
| ---------           | :----: |
| `RSASSA-PKCS1-v1_5` |  |
| `RSA-PSS`           |  |
| `ECDSA`             |  |
| `Ed25519`           |  |
| `Ed448`             |  |
| `HMAC`              |  |

## `verify`
| Algorithm           | Status |
| ---------           | :----: |
| `RSASSA-PKCS1-v1_5` |  |
| `RSA-PSS`           |  |
| `ECDSA`             |  |
| `Ed25519`           |  |
| `Ed448`             |  |
| `HMAC`              |  |

## `digest`
| Algorithm  | Status |
| ---------  | :----: |
| `SHA-1`    | ✅ |
| `SHA-256`  | ✅ |
| `SHA-384`  | ✅ |
| `SHA-512`  | ✅ |

## `generateKey`

### `CryptoKeyPair` algorithms
| Algorithm           | Status |
| ---------           | :----: |
| `RSASSA-PKCS1-v1_5` |  |
| `RSA-PSS`           |  |
| `RSA-OAEP`          |  |
| `ECDSA`             |  |
| `Ed25519`           |  |
| `Ed448`             |  |
| `ECDH`              |  |
| `X25519`            |  |
| `X448`              |  |

### `CryptoKey` algorithms
| Algorithm    | Status |
| ---------    | :----: |
| `HMAC`       |  |
| `AES-CTR`    |  |
| `AES-CBC`    |  |
| `AES-GCM`    |  |
| `AES-KW`     |  |

## `deriveKey`
| Algorithm  | Status |
| ---------  | :----: |
| `ECDH`     |  |
| `X25519`   |  |
| `X448`     |  |
| `HKDF`     |  |
| `PBKDF2`   |  |

## `deriveBits`
| Algorithm  | Status |
| ---------  | :----: |
| `ECDH`     |  |
| `X25519`   |  |
| `X448`     |  |
| `HKDF`     |  |
| `PBKDF2`   | ✅ |

## `importKey`
| Key Type            | `spki` | `pkcs8` | `jwk` | `raw` |
| ------------------- | :----: | :-----: | :---: | :---: |
| `AES-CBC`           |   |   | ✅ | ✅ |
| `AES-CTR`           |   |   | ✅ | ✅ |
| `AES-GCM`           |   |   | ✅ | ✅ |
| `AES-KW`            |   |   | ✅ | ✅ |
| `ECDH`              | ❌ | ❌ | ✅ | ✅ |
| `X25519`            | ❌ | ❌ | ❌ | ❌ |
| `X448`              | ❌ | ❌ | ❌ | ❌ |
| `ECDSA`             | ❌ | ❌ | ✅ | ✅ |
| `Ed25519`           | ❌ | ❌ | ❌ | ❌ |
| `Ed448`             | ❌ | ❌ | ❌ | ❌ |
| `HDKF`              |   |   |   |   |
| `HMAC`              |   |   | ❌ | ❌ |
| `PBKDF2`            |   |   |   | ✅ |
| `RSA-OAEP`          | ❌ | ❌ | ✅ |   |
| `RSA-PSS`           | ❌ | ❌ | ✅ |   |
| `RSASSA-PKCS1-v1_5` | ❌ | ❌ | ✅ |   |

* ` ` - not implemented in Node
* ❌ - implemented in Node, not RNQC
* ✅ - implemented in Node and RNQC

## `exportKey`
| Key Type            | `spki` | `pkcs8` | `jwk` | `raw` |
| ------------------- | :----: | :-----: | :---: | :---: |
| `AES-CBC`           |   |   | ✅ | ✅ |
| `AES-CTR`           |   |   | ✅ | ✅ |
| `AES-GCM`           |   |   | ✅ | ✅ |
| `AES-KW`            |   |   | ✅ | ✅ |
| `ECDH`              | ✅ | ❌ | ✅ | ✅ |
| `ECDSA`             | ✅ | ❌ | ✅ | ✅ |
| `Ed25519`           | ❌ | ❌ | ❌ | ❌ |
| `Ed448`             | ❌ | ❌ | ❌ | ❌ |
| `HDKF`              |   |   |   |   |
| `HMAC`              |   |   | ❌ | ❌ |
| `PBKDF2`            |   |   |   |   |
| `RSA-OAEP`          | ❌ | ❌ | ✅ |   |
| `RSA-PSS`           | ❌ | ❌ | ✅ |   |
| `RSASSA-PKCS1-v1_5` | ❌ | ❌ | ✅ |   |

* ` ` - not implemented in Node
* ❌ - implemented in Node, not RNQC
* ✅ - implemented in Node and RNQC

## `wrapKey`

### wrapping algorithms
| Algorithm  | Status |
| ---------  | :----: |
| `RSA-OAEP` |  |
| `AES-CTR`  |  |
| `AES-CBC`  |  |
| `AES-GCM`  |  |
| `AES-KW`   |  |

## `unwrapKey`

### wrapping algorithms
| Algorithm  | Status |
| ---------  | :----: |
| `RSA-OAEP` |  |
| `AES-CTR`  |  |
| `AES-CBC`  |  |
| `AES-GCM`  |  |
| `AES-KW`   |  |

### unwrapped key algorithms
| Algorithm           | Status |
| ---------           | :----: |
| `RSASSA-PKCS1-v1_5` |  |
| `RSA-PSS`           |  |
| `RSA-OAEP`          |  |
| `ECDSA`             |  |
| `Ed25519`           |  |
| `Ed448`             |  |
| `ECDH`              |  |
| `X25519`            |  |
| `X448`              |  |
| `HMAC`              |  |
| `AES-CTR`           |  |
| `AES-CBC`           |  |
| `AES-GCM`           |  |
| `AES-KW`            |  |
