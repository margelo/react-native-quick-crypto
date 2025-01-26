# Implementation Coverage
This document attempts to describe the implementation status of Crypto APIs/Interfaces from Node.js in the `react-native-quick-crypto` library.

> Note: This is the status for version 1.x and higher. For version `0.x` see [this document](https://github.com/margelo/react-native-quick-crypto/blob/0.x/docs/implementation-coverage.md) and the [0.x branch](https://github.com/margelo/react-native-quick-crypto/tree/0.x).

* ❌ - implemented in Node, not RNQC
* ✅ - implemented in Node and RNQC

# `Crypto`

* ❌ Class: `Certificate`
   * ❌ Static method: `Certificate.exportChallenge(spkac[, encoding])`
   * ❌ Static method: `Certificate.exportPublicKey(spkac[, encoding])`
   * ❌ Static method: `Certificate.verifySpkac(spkac[, encoding])`
* ✅ Class: `Cipher`
  * ✅ `cipher.final([outputEncoding])`
  * ✅ `cipher.getAuthTag()`
  * ✅ `cipher.setAAD(buffer[, options])`
  * ✅ `cipher.setAutoPadding([autoPadding])`
  * ✅ `cipher.update(data[, inputEncoding][, outputEncoding])`
* ✅ Class: `Decipher`
  * ✅ `decipher.final([outputEncoding])`
  * ✅ `decipher.setAAD(buffer[, options])`
  * ✅ `decipher.setAuthTag(buffer[, encoding])`
  * ✅ `decipher.setAutoPadding([autoPadding])`
  * ✅ `decipher.update(data[, inputEncoding][, outputEncoding])`
* ❌ Class: `DiffieHellman`
  * ❌ `diffieHellman.computeSecret(otherPublicKey[, inputEncoding][, outputEncoding])`
  * ❌ `diffieHellman.generateKeys([encoding])`
  * ❌ `diffieHellman.getGenerator([encoding])`
  * ❌ `diffieHellman.getPrime([encoding])`
  * ❌ `diffieHellman.getPrivateKey([encoding])`
  * ❌ `diffieHellman.getPublicKey([encoding])`
  * ❌ `diffieHellman.setPrivateKey(privateKey[, encoding])`
  * ❌ `diffieHellman.setPublicKey(publicKey[, encoding])`
  * ❌ `diffieHellman.verifyError`
* ❌ Class: `DiffieHellmanGroup`
* ❌ Class: `ECDH`
  * ❌ `Static method: ECDH.convertKey(key, curve[, inputEncoding[, outputEncoding[, format]]])`
  * ❌ `ecdh.computeSecret(otherPublicKey[, inputEncoding][, outputEncoding])`
  * ❌ `ecdh.generateKeys([encoding[, format]])`
  * ❌ `ecdh.getPrivateKey([encoding])`
  * ❌ `ecdh.getPublicKey([encoding][, format])`
  * ❌ `ecdh.setPrivateKey(privateKey[, encoding])`
  * ❌ `ecdh.setPublicKey(publicKey[, encoding])`
* ✅ Class: `Hash`
  * ✅ `hash.copy([options])`
  * ✅ `hash.digest([encoding])`
  * ✅ `hash.update(data[, inputEncoding])`
* ❌ Class: `Hmac`
  * ❌ `hmac.digest([encoding])`
  * ❌ `hmac.update(data[, inputEncoding])`
* ❌ Class: `KeyObject`
  * ❌ `Static method: KeyObject.from(key)`
  * ❌ `keyObject.asymmetricKeyDetails`
  * ❌ `keyObject.asymmetricKeyType`
  * ❌ `keyObject.export([options])`
  * ❌ `keyObject.equals(otherKeyObject)`
  * ❌ `keyObject.symmetricKeySize`
  * ❌ `keyObject.type`
* ❌ Class: `Sign`
  * ❌ `sign.sign(privateKey[, outputEncoding])`
  * ❌ `sign.update(data[, inputEncoding])`
* ❌ Class: `Verify`
  * ❌ `verify.update(data[, inputEncoding])`
  * ❌ `verify.verify(object, signature[, signatureEncoding])`
* ❌ Class: `X509Certificate`
  * ❌ `new X509Certificate(buffer)`
  * ❌ `x509.ca`
  * ❌ `x509.checkEmail(email[, options])`
  * ❌ `x509.checkHost(name[, options])`
  * ❌ `x509.checkIP(ip)`
  * ❌ `x509.checkIssued(otherCert)`
  * ❌ `x509.checkPrivateKey(privateKey)`
  * ❌ `x509.fingerprint`
  * ❌ `x509.fingerprint256`
  * ❌ `x509.fingerprint512`
  * ❌ `x509.infoAccess`
  * ❌ `x509.issuer`
  * ❌ `x509.issuerCertificate`
  * ❌ `x509.extKeyUsage`
  * ❌ `x509.publicKey`
  * ❌ `x509.raw`
  * ❌ `x509.serialNumber`
  * ❌ `x509.subject`
  * ❌ `x509.subjectAltName`
  * ❌ `x509.toJSON()`
  * ❌ `x509.toLegacyObject()`
  * ❌ `x509.toString()`
  * ❌ `x509.validFrom`
  * ❌ `x509.validTo`
  * ❌ `x509.verify(publicKey)`
* 🚧 node:crypto module methods and properties
  * ❌ `crypto.constants`
  * ❌ `crypto.fips`
  * ❌ `crypto.checkPrime(candidate[, options], callback)`
  * ❌ `crypto.checkPrimeSync(candidate[, options])`
  * ✅ `crypto.createCipheriv(algorithm, key, iv[, options])`
  * ✅ `crypto.createDecipheriv(algorithm, key, iv[, options])`
  * ❌ `crypto.createDiffieHellman(prime[, primeEncoding][, generator][, generatorEncoding])`
  * ❌ `crypto.createDiffieHellman(primeLength[, generator])`
  * ❌ `crypto.createDiffieHellmanGroup(name)`
  * ❌ `crypto.createECDH(curveName)`
  * ✅ `crypto.createHash(algorithm[, options])`
  * ❌ `crypto.createHmac(algorithm, key[, options])`
  * ❌ `crypto.createPrivateKey(key)`
  * ❌ `crypto.createPublicKey(key)`
  * ❌ `crypto.createSecretKey(key[, encoding])`
  * ❌ `crypto.createSign(algorithm[, options])`
  * ❌ `crypto.createVerify(algorithm[, options])`
  * ❌ `crypto.diffieHellman(options)`
  * ❌ `crypto.hash(algorithm, data[, outputEncoding])`
  * ❌ `crypto.generateKey(type, options, callback)`
  * 🚧 `crypto.generateKeyPair(type, options, callback)`
  * 🚧 `crypto.generateKeyPairSync(type, options)`
  * ❌ `crypto.generateKeySync(type, options)`
  * ❌ `crypto.generatePrime(size[, options[, callback]])`
  * ❌ `crypto.generatePrimeSync(size[, options])`
  * ❌ `crypto.getCipherInfo(nameOrNid[, options])`
  * ✅ `crypto.getCiphers()`
  * ❌ `crypto.getCurves()`
  * ❌ `crypto.getDiffieHellman(groupName)`
  * ❌ `crypto.getFips()`
  * ❌ `crypto.getHashes()`
  * ❌ `crypto.getRandomValues(typedArray)`
  * ❌ `crypto.hkdf(digest, ikm, salt, info, keylen, callback)`
  * ❌ `crypto.hkdfSync(digest, ikm, salt, info, keylen)`
  * ✅ `crypto.pbkdf2(password, salt, iterations, keylen, digest, callback)`
  * ✅ `crypto.pbkdf2Sync(password, salt, iterations, keylen, digest)`
  * ❌ `crypto.privateDecrypt(privateKey, buffer)`
  * ❌ `crypto.privateEncrypt(privateKey, buffer)`
  * ❌ `crypto.publicDecrypt(key, buffer)`
  * ❌ `crypto.publicEncrypt(key, buffer)`
  * ✅ `crypto.randomBytes(size[, callback])`
  * ✅ `crypto.randomFillSync(buffer[, offset][, size])`
  * ✅ `crypto.randomFill(buffer[, offset][, size], callback)`
  * ✅ `crypto.randomInt([min, ]max[, callback])`
  * ✅ `crypto.randomUUID([options])`
  * ❌ `crypto.scrypt(password, salt, keylen[, options], callback)`
  * ❌ `crypto.scryptSync(password, salt, keylen[, options])`
  * ❌ `crypto.secureHeapUsed()`
  * ❌ `crypto.setEngine(engine[, flags])`
  * ❌ `crypto.setFips(bool)`
  * 🚧 `crypto.sign(algorithm, data, key[, callback])`
  * ❌ `crypto.subtle` (see below)
  * ❌ `crypto.timingSafeEqual(a, b)`
  * 🚧 `crypto.verify(algorithm, data, key, signature[, callback])`
  * ❌ `crypto.webcrypto` (see below)

🚧 Details below still a work in progress 🚧

## `crypto.generateKey`
| type       | Status |
| ---------  | :----: |
| `aes`      | ❌ |
| `hmac`     | ❌ |

## `crypto.generateKeyPair`
| type      | Status |
| --------- | :----: |
| `rsa`     | ❌ |
| `rsa-pss` | ❌ |
| `dsa`     | ❌ |
| `ec`      | ❌ |
| `ed25519` | ✅ |
| `ed448`   | ✅ |
| `x25519`  | ✅ |
| `x448`    | ✅ |
| `dh`      | ❌ |

## `crypto.generateKeyPairSync`
| type      | Status |
| --------- | :----: |
| `rsa`     | ❌ |
| `rsa-pss` | ❌ |
| `dsa`     | ❌ |
| `ec`      | ❌ |
| `ed25519` | ✅ |
| `ed448`   | ✅ |
| `x25519`  | ✅ |
| `x448`    | ✅ |
| `dh`      | ❌ |

## `crypto.generateKeySync`
| type       | Status |
| ---------  | :----: |
| `aes`      | ❌ |
| `hmac`     | ❌ |

## `crypto.sign`
| Algorithm           | Status |
| ---------           | :----: |
| `RSASSA-PKCS1-v1_5` |  |
| `RSA-PSS`           |  |
| `ECDSA`             |  |
| `Ed25519`           | ✅ |
| `Ed448`             | ✅ |
| `HMAC`              |  |

## `crypto.verify`
| Algorithm           | Status |
| ---------           | :----: |
| `RSASSA-PKCS1-v1_5` |  |
| `RSA-PSS`           |  |
| `ECDSA`             |  |
| `Ed25519`           | ✅ |
| `Ed448`             | ✅ |
| `HMAC`              |  |

# `WebCrypto`

* ❌ Class: `Crypto`
  * ❌ `crypto.subtle`
  * ❌ `crypto.getRandomValues(typedArray)`
  * ❌ `crypto.randomUUID()`
* ❌ Class: `CryptoKey`
  * ❌ `cryptoKey.algorithm`
  * ❌ `cryptoKey.extractable`
  * ❌ `cryptoKey.type`
  * ❌ `cryptoKey.usages`
* ❌ Class: `CryptoKeyPair`
  * ❌ `cryptoKeyPair.privateKey`
  * ❌ `cryptoKeyPair.publicKey`
* ❌ Class: `CryptoSubtle`
  * (see below)

# `SubtleCrypto`

* ❌ Class: `SubtleCrypto`
  * ❌ `subtle.decrypt(algorithm, key, data)`
  * ❌ `subtle.deriveBits(algorithm, baseKey, length)`
  * ❌ `subtle.deriveKey(algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsages)`
  * ❌ `subtle.digest(algorithm, data)`
  * ❌ `subtle.encrypt(algorithm, key, data)`
  * ❌ `subtle.exportKey(format, key)`
  * ❌ `subtle.generateKey(algorithm, extractable, keyUsages)`
  * ❌ `subtle.importKey(format, keyData, algorithm, extractable, keyUsages)`
  * ❌ `subtle.sign(algorithm, key, data)`
  * ❌ `subtle.unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgo, unwrappedKeyAlgo, extractable, keyUsages)`
  * ❌ `subtle.verify(algorithm, key, signature, data)`
  * ❌ `subtle.wrapKey(format, key, wrappingKey, wrapAlgo)`

## `subtle.decrypt`
| Algorithm  | Status |
| ---------  | :----: |
| `RSA-OAEP` | ❌ |
| `AES-CTR`  | ❌ |
| `AES-CBC`  | ❌ |
| `AES-GCM`  | ❌ |

## `subtle.deriveBits`
| Algorithm  | Status |
| ---------  | :----: |
| `ECDH`     |  |
| `X25519`   |  |
| `X448`     |  |
| `HKDF`     |  |
| `PBKDF2`   | ❌ |

## `subtle.deriveKey`
| Algorithm  | Status |
| ---------  | :----: |
| `ECDH`     |  |
| `X25519`   |  |
| `X448`     |  |
| `HKDF`     |  |
| `PBKDF2`   |  |

## `subtle.digest`
| Algorithm  | Status |
| ---------  | :----: |
| `SHA-1`    | ❌ |
| `SHA-256`  | ❌ |
| `SHA-384`  | ❌ |
| `SHA-512`  | ❌ |

## `subtle.encrypt`
| Algorithm  | Status |
| ---------  | :----: |
| `RSA-OAEP` | ❌ |
| `AES-CTR`  | ❌ |
| `AES-CBC`  | ❌ |
| `AES-GCM`  | ❌ |

## `subtle.exportKey`
| Key Type            | `spki` | `pkcs8` | `jwk` | `raw` |
| ------------------- | :----: | :-----: | :---: | :---: |
| `AES-CBC`           |   |   | ❌ | ❌ |
| `AES-CTR`           |   |   | ❌ | ❌ |
| `AES-GCM`           |   |   | ❌ | ❌ |
| `AES-KW`            |   |   | ❌ | ❌ |
| `ECDH`              | ❌ | ❌ | ❌ | ❌ |
| `ECDSA`             | ❌ | ❌ | ❌ | ❌ |
| `Ed25519`           | ❌ | ❌ | ❌ | ❌ |
| `Ed448`             | ❌ | ❌ | ❌ | ❌ |
| `HDKF`              |   |   |   |   |
| `HMAC`              |   |   | ❌ | ❌ |
| `PBKDF2`            |   |   |   |   |
| `RSA-OAEP`          | ❌ | ❌ | ❌ |   |
| `RSA-PSS`           | ❌ | ❌ | ❌ |   |
| `RSASSA-PKCS1-v1_5` | ❌ | ❌ | ❌ |   |

* ` ` - not implemented in Node
* ❌ - implemented in Node, not RNQC
* ✅ - implemented in Node and RNQC

## `subtle.generateKey`

### `CryptoKeyPair` algorithms
| Algorithm           | Status |
| ---------           | :----: |
| `RSASSA-PKCS1-v1_5` | ❌ |
| `RSA-PSS`           | ❌ |
| `RSA-OAEP`          | ❌ |
| `ECDSA`             | ❌ |
| `Ed25519`           | ❌ |
| `Ed448`             |  |
| `ECDH`              |  |
| `X25519`            |  |
| `X448`              |  |

### `CryptoKey` algorithms
| Algorithm  | Status |
| ---------  | :----: |
| `HMAC`     |  |
| `AES-CTR`  | ❌ |
| `AES-CBC`  | ❌ |
| `AES-GCM`  | ❌ |
| `AES-KW`   | ❌ |

## `subtle.importKey`
| Key Type            | `spki` | `pkcs8` | `jwk` | `raw` |
| ------------------- | :----: | :-----: | :---: | :---: |
| `AES-CBC`           |   |   | ❌ | ❌ |
| `AES-CTR`           |   |   | ❌ | ❌ |
| `AES-GCM`           |   |   | ❌ | ❌ |
| `AES-KW`            |   |   | ❌ | ❌ |
| `ECDH`              | ❌ | ❌ | ❌ | ❌ |
| `X25519`            | ❌ | ❌ | ❌ | ❌ |
| `X448`              | ❌ | ❌ | ❌ | ❌ |
| `ECDSA`             | ❌ | ❌ | ❌ | ❌ |
| `Ed25519`           | ❌ | ❌ | ❌ | ❌ |
| `Ed448`             | ❌ | ❌ | ❌ | ❌ |
| `HDKF`              |   |   |   |   |
| `HMAC`              |   |   | ❌ | ❌ |
| `PBKDF2`            |   |   |   | ❌ |
| `RSA-OAEP`          | ❌ | ❌ | ❌ |   |
| `RSA-PSS`           | ❌ | ❌ | ❌ |   |
| `RSASSA-PKCS1-v1_5` | ❌ | ❌ | ❌ |   |

* ` ` - not implemented in Node
* ❌ - implemented in Node, not RNQC
* ✅ - implemented in Node and RNQC

## `subtle.sign`
| Algorithm           | Status |
| ---------           | :----: |
| `RSASSA-PKCS1-v1_5` |  |
| `RSA-PSS`           |  |
| `ECDSA`             | ❌ |
| `Ed25519`           |  |
| `Ed448`             |  |
| `HMAC`              |  |

## `subtle.unwrapKey`

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

## `subtle.verify`
| Algorithm           | Status |
| ---------           | :----: |
| `RSASSA-PKCS1-v1_5` |  |
| `RSA-PSS`           |  |
| `ECDSA`             | ❌ |
| `Ed25519`           |  |
| `Ed448`             |  |
| `HMAC`              |  |

## `subtle.wrapKey`

### wrapping algorithms
| Algorithm  | Status |
| ---------  | :----: |
| `RSA-OAEP` |  |
| `AES-CTR`  |  |
| `AES-CBC`  |  |
| `AES-GCM`  |  |
| `AES-KW`   |  |
