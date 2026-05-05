/* eslint-disable @typescript-eslint/no-unused-vars */
import { Buffer as SBuffer } from 'safe-buffer';
import type {
  SubtleAlgorithm,
  KeyUsage,
  BinaryLike,
  BufferLike,
  JWK,
  AnyAlgorithm,
  ImportFormat,
  AesKeyGenParams,
  EncryptDecryptParams,
  Operation,
  AesCtrParams,
  AesCbcParams,
  AesGcmParams,
  AesOcbParams,
  RsaOaepParams,
  ChaCha20Poly1305Params,
} from './utils';
import { KFormatType, KeyEncoding, KeyType } from './utils';
import {
  CryptoKey,
  KeyObject,
  PublicKeyObject,
  PrivateKeyObject,
  SecretKeyObject,
} from './keys';
import type { CryptoKeyPair } from './utils/types';
import { bufferLikeToArrayBuffer } from './utils/conversion';
import { argon2Sync } from './argon2';
import { lazyDOMException } from './utils/errors';
import { normalizeHashName, HashContext } from './utils/hashnames';
import {
  validateJwkStructure,
  validateMaxBufferLength,
} from './utils/validation';
import { asyncDigest } from './hash';
import { createSecretKey, createPublicKey } from './keys';
import { NitroModules } from 'react-native-nitro-modules';
import type { KeyObjectHandle } from './specs/keyObjectHandle.nitro';
import type { RsaCipher } from './specs/rsaCipher.nitro';
import type { CipherFactory } from './specs/cipher.nitro';
import { pbkdf2DeriveBits } from './pbkdf2';
import {
  ecImportKey,
  ecdsaSignVerify,
  ec_generateKeyPair,
  ecDeriveBits,
} from './ec';
import { rsa_generateKeyPair } from './rsa';
import { getRandomValues } from './random';
import { createHmac } from './hmac';
import type { Kmac } from './specs/kmac.nitro';
import { timingSafeEqual } from './utils/timingSafeEqual';
import { createSign, createVerify } from './keys/signVerify';
import {
  ed_generateKeyPairWebCrypto,
  x_generateKeyPairWebCrypto,
  xDeriveBits,
  Ed,
} from './ed';
import { mldsa_generateKeyPairWebCrypto, type MlDsaVariant } from './mldsa';
import {
  mlkem_generateKeyPairWebCrypto,
  type MlKemVariant,
  MlKem,
} from './mlkem';
import type { EncapsulateResult } from './utils';
import { hkdfDeriveBits, type HkdfAlgorithm } from './hkdf';
// Temporary enums that need to be defined

enum KWebCryptoKeyFormat {
  kWebCryptoKeyFormatRaw,
  kWebCryptoKeyFormatSPKI,
  kWebCryptoKeyFormatPKCS8,
}

enum CipherOrWrapMode {
  kWebCryptoCipherEncrypt,
  kWebCryptoCipherDecrypt,
}

// Placeholder functions that need to be implemented
function hasAnyNotIn(usages: KeyUsage[], allowed: KeyUsage[]): boolean {
  return usages.some(usage => !allowed.includes(usage));
}

// WebCrypto §18.4.4: algorithm name lookup is case-insensitive, but the
// canonical mixed-case form is preserved in the resulting `name` field
// (e.g. "aes-gcm" → "AES-GCM"). This map is built lazily on first call so
// the registry of canonical names below can stay declared after the
// function. Without this, callers who pass lowercase strings bypass the
// downstream `SUPPORTED_ALGORITHMS` set comparisons silently.
//
// The map's value type is `AnyAlgorithm` so callers can use the lookup
// result directly without re-asserting. The `as AnyAlgorithm` at insertion
// is the single contract boundary: every name in `SUPPORTED_ALGORITHMS` is
// already a member of `AnyAlgorithm` by construction.
let _canonicalAlgorithmNames: Map<string, AnyAlgorithm> | null = null;
function getCanonicalAlgorithmNames(): Map<string, AnyAlgorithm> {
  if (_canonicalAlgorithmNames === null) {
    const map = new Map<string, AnyAlgorithm>();
    for (const set of Object.values(SUPPORTED_ALGORITHMS)) {
      if (!set) continue;
      for (const name of set) {
        map.set(name.toLowerCase(), name as AnyAlgorithm);
      }
    }
    _canonicalAlgorithmNames = map;
  }
  return _canonicalAlgorithmNames;
}

function normalizeAlgorithm(
  algorithm: SubtleAlgorithm | AnyAlgorithm,
  _operation: Operation,
): SubtleAlgorithm {
  const map = getCanonicalAlgorithmNames();
  if (typeof algorithm === 'string') {
    return { name: map.get(algorithm.toLowerCase()) ?? algorithm };
  }
  if (typeof algorithm.name === 'string') {
    const canonical = map.get(algorithm.name.toLowerCase()) ?? algorithm.name;
    return { ...algorithm, name: canonical };
  }
  return algorithm as SubtleAlgorithm;
}

function getAlgorithmName(name: string, length: number): string {
  switch (name) {
    case 'AES-CBC':
      return `A${length}CBC`;
    case 'AES-CTR':
      return `A${length}CTR`;
    case 'AES-GCM':
      return `A${length}GCM`;
    case 'AES-KW':
      return `A${length}KW`;
    case 'AES-OCB':
      return `A${length}OCB`;
    case 'ChaCha20-Poly1305':
      return 'C20P';
    default:
      return `${name}${length}`;
  }
}

// Mirrors Node's aliasKeyFormat (lib/internal/crypto/webcrypto.js): for
// algorithms whose import/export accepts both 'raw' and the disambiguated
// 'raw-secret' / 'raw-public', collapse the latter to 'raw'. Used per-algorithm
// — algorithms that demand the disambiguated form (KMAC, AES-OCB,
// ChaCha20-Poly1305, Argon2*, ML-DSA, ML-KEM) MUST NOT alias.
function aliasKeyFormat(format: ImportFormat): ImportFormat {
  if (format === 'raw-secret' || format === 'raw-public') return 'raw';
  return format;
}

// Placeholder implementations for missing functions
function ecExportKey(key: CryptoKey, format: KWebCryptoKeyFormat): ArrayBuffer {
  const keyObject = key.keyObject;

  if (format === KWebCryptoKeyFormat.kWebCryptoKeyFormatRaw) {
    return bufferLikeToArrayBuffer(keyObject.handle.exportKey());
  } else if (format === KWebCryptoKeyFormat.kWebCryptoKeyFormatSPKI) {
    const exported = keyObject.export({ format: 'der', type: 'spki' });
    return bufferLikeToArrayBuffer(exported);
  } else if (format === KWebCryptoKeyFormat.kWebCryptoKeyFormatPKCS8) {
    const exported = keyObject.export({ format: 'der', type: 'pkcs8' });
    return bufferLikeToArrayBuffer(exported);
  } else {
    throw new Error(`Unsupported EC export format: ${format}`);
  }
}

function rsaExportKey(
  key: CryptoKey,
  format: KWebCryptoKeyFormat,
): ArrayBuffer {
  const keyObject = key.keyObject;

  if (format === KWebCryptoKeyFormat.kWebCryptoKeyFormatSPKI) {
    // Export public key in SPKI format
    const exported = keyObject.export({ format: 'der', type: 'spki' });
    return bufferLikeToArrayBuffer(exported);
  } else if (format === KWebCryptoKeyFormat.kWebCryptoKeyFormatPKCS8) {
    // Export private key in PKCS8 format
    const exported = keyObject.export({ format: 'der', type: 'pkcs8' });
    return bufferLikeToArrayBuffer(exported);
  } else {
    throw new Error(`Unsupported RSA export format: ${format}`);
  }
}

async function rsaCipher(
  mode: CipherOrWrapMode,
  key: CryptoKey,
  data: ArrayBuffer,
  algorithm: EncryptDecryptParams,
): Promise<ArrayBuffer> {
  const rsaParams = algorithm as RsaOaepParams;

  // Validate key type matches operation
  const expectedType =
    mode === CipherOrWrapMode.kWebCryptoCipherEncrypt ? 'public' : 'private';
  if (key.type !== expectedType) {
    throw lazyDOMException(
      'The requested operation is not valid for the provided key',
      'InvalidAccessError',
    );
  }

  // Get hash algorithm from key
  const hashAlgorithm = normalizeHashName(key.algorithm.hash);

  // Prepare label (optional)
  const label = rsaParams.label
    ? bufferLikeToArrayBuffer(rsaParams.label)
    : undefined;

  // Create RSA cipher instance
  const rsaCipherModule =
    NitroModules.createHybridObject<RsaCipher>('RsaCipher');

  // RSA-OAEP padding constant = 4
  const RSA_PKCS1_OAEP_PADDING = 4;

  if (mode === CipherOrWrapMode.kWebCryptoCipherEncrypt) {
    // Encrypt with public key
    return rsaCipherModule.encrypt(
      key.keyObject.handle,
      data,
      RSA_PKCS1_OAEP_PADDING,
      hashAlgorithm,
      label,
    );
  } else {
    // Decrypt with private key
    return rsaCipherModule.decrypt(
      key.keyObject.handle,
      data,
      RSA_PKCS1_OAEP_PADDING,
      hashAlgorithm,
      label,
    );
  }
}

async function aesCipher(
  mode: CipherOrWrapMode,
  key: CryptoKey,
  data: ArrayBuffer,
  algorithm: EncryptDecryptParams,
): Promise<ArrayBuffer> {
  const { name } = algorithm;

  switch (name) {
    case 'AES-CTR':
      return aesCtrCipher(mode, key, data, algorithm as AesCtrParams);
    case 'AES-CBC':
      return aesCbcCipher(mode, key, data, algorithm as AesCbcParams);
    case 'AES-GCM':
      return aesGcmCipher(mode, key, data, algorithm as AesGcmParams);
    case 'AES-OCB':
      return aesOcbCipher(mode, key, data, algorithm as AesOcbParams);
    default:
      throw lazyDOMException(
        `Unsupported AES algorithm: ${name}`,
        'NotSupportedError',
      );
  }
}

async function aesCtrCipher(
  mode: CipherOrWrapMode,
  key: CryptoKey,
  data: ArrayBuffer,
  algorithm: AesCtrParams,
): Promise<ArrayBuffer> {
  // Validate counter and length
  if (!algorithm.counter || algorithm.counter.byteLength !== 16) {
    throw lazyDOMException(
      'AES-CTR algorithm.counter must be 16 bytes',
      'OperationError',
    );
  }

  if (algorithm.length < 1 || algorithm.length > 128) {
    throw lazyDOMException(
      'AES-CTR algorithm.length must be between 1 and 128',
      'OperationError',
    );
  }

  // Get cipher type based on key length
  const keyLength = (key.algorithm as { length: number }).length;
  const cipherType = `aes-${keyLength}-ctr`;

  // Create cipher
  const factory =
    NitroModules.createHybridObject<CipherFactory>('CipherFactory');
  const cipher = factory.createCipher({
    isCipher: mode === CipherOrWrapMode.kWebCryptoCipherEncrypt,
    cipherType,
    cipherKey: bufferLikeToArrayBuffer(key.keyObject.export()),
    iv: bufferLikeToArrayBuffer(algorithm.counter),
  });

  // Process data
  const updated = cipher.update(data);
  const final = cipher.final();

  // Concatenate results
  const result = new Uint8Array(updated.byteLength + final.byteLength);
  result.set(new Uint8Array(updated), 0);
  result.set(new Uint8Array(final), updated.byteLength);

  return result.buffer;
}

async function aesCbcCipher(
  mode: CipherOrWrapMode,
  key: CryptoKey,
  data: ArrayBuffer,
  algorithm: AesCbcParams,
): Promise<ArrayBuffer> {
  // Validate IV
  const iv = bufferLikeToArrayBuffer(algorithm.iv);
  if (iv.byteLength !== 16) {
    throw lazyDOMException(
      'algorithm.iv must contain exactly 16 bytes',
      'OperationError',
    );
  }

  // Get cipher type based on key length
  const keyLength = (key.algorithm as { length: number }).length;
  const cipherType = `aes-${keyLength}-cbc`;

  // Create cipher
  const factory =
    NitroModules.createHybridObject<CipherFactory>('CipherFactory');
  const cipher = factory.createCipher({
    isCipher: mode === CipherOrWrapMode.kWebCryptoCipherEncrypt,
    cipherType,
    cipherKey: bufferLikeToArrayBuffer(key.keyObject.export()),
    iv,
  });

  // Process data
  const updated = cipher.update(data);
  const final = cipher.final();

  // Concatenate results
  const result = new Uint8Array(updated.byteLength + final.byteLength);
  result.set(new Uint8Array(updated), 0);
  result.set(new Uint8Array(final), updated.byteLength);

  return result.buffer;
}

interface AeadCipherConfig {
  algorithmName: string;
  validTagLengths: number[];
  cipherSuffix: string;
  iv: ArrayBuffer;
}

async function aesAeadCipher(
  mode: CipherOrWrapMode,
  key: CryptoKey,
  data: ArrayBuffer,
  config: AeadCipherConfig,
  additionalData?: BufferLike,
  tagLength: number = 128,
): Promise<ArrayBuffer> {
  if (!config.validTagLengths.includes(tagLength)) {
    throw lazyDOMException(
      `${tagLength} is not a valid ${config.algorithmName} tag length`,
      'OperationError',
    );
  }

  const tagByteLength = tagLength / 8;
  const keyLength = (key.algorithm as { length: number }).length;
  const cipherType = `aes-${keyLength}-${config.cipherSuffix}`;

  const factory =
    NitroModules.createHybridObject<CipherFactory>('CipherFactory');
  const cipher = factory.createCipher({
    isCipher: mode === CipherOrWrapMode.kWebCryptoCipherEncrypt,
    cipherType,
    cipherKey: bufferLikeToArrayBuffer(key.keyObject.export()),
    iv: config.iv,
    authTagLen: tagByteLength,
  });

  let processData: ArrayBuffer;

  if (mode === CipherOrWrapMode.kWebCryptoCipherDecrypt) {
    const dataView = new Uint8Array(data);

    if (dataView.byteLength < tagByteLength) {
      throw lazyDOMException(
        'The provided data is too small.',
        'OperationError',
      );
    }

    const ciphertextLength = dataView.byteLength - tagByteLength;
    processData = dataView.slice(0, ciphertextLength).buffer;
    const authTag = dataView.slice(ciphertextLength).buffer;
    cipher.setAuthTag(authTag);
  } else {
    processData = data;
  }

  if (additionalData) {
    cipher.setAAD(bufferLikeToArrayBuffer(additionalData));
  }

  const updated = cipher.update(processData);
  const final = cipher.final();

  if (mode === CipherOrWrapMode.kWebCryptoCipherEncrypt) {
    const tag = cipher.getAuthTag();
    const result = new Uint8Array(
      updated.byteLength + final.byteLength + tag.byteLength,
    );
    result.set(new Uint8Array(updated), 0);
    result.set(new Uint8Array(final), updated.byteLength);
    result.set(new Uint8Array(tag), updated.byteLength + final.byteLength);
    return result.buffer;
  } else {
    const result = new Uint8Array(updated.byteLength + final.byteLength);
    result.set(new Uint8Array(updated), 0);
    result.set(new Uint8Array(final), updated.byteLength);
    return result.buffer;
  }
}

async function aesGcmCipher(
  mode: CipherOrWrapMode,
  key: CryptoKey,
  data: ArrayBuffer,
  algorithm: AesGcmParams,
): Promise<ArrayBuffer> {
  return aesAeadCipher(
    mode,
    key,
    data,
    {
      algorithmName: 'AES-GCM',
      validTagLengths: [32, 64, 96, 104, 112, 120, 128],
      cipherSuffix: 'gcm',
      iv: bufferLikeToArrayBuffer(algorithm.iv),
    },
    algorithm.additionalData,
    algorithm.tagLength,
  );
}

async function aesOcbCipher(
  mode: CipherOrWrapMode,
  key: CryptoKey,
  data: ArrayBuffer,
  algorithm: AesOcbParams,
): Promise<ArrayBuffer> {
  const ivBuffer = bufferLikeToArrayBuffer(algorithm.iv);
  if (ivBuffer.byteLength < 1 || ivBuffer.byteLength > 15) {
    throw lazyDOMException(
      'AES-OCB algorithm.iv must be between 1 and 15 bytes',
      'OperationError',
    );
  }

  return aesAeadCipher(
    mode,
    key,
    data,
    {
      algorithmName: 'AES-OCB',
      validTagLengths: [64, 96, 128],
      cipherSuffix: 'ocb',
      iv: ivBuffer,
    },
    algorithm.additionalData,
    algorithm.tagLength,
  );
}

async function aesKwCipher(
  mode: CipherOrWrapMode,
  key: CryptoKey,
  data: ArrayBuffer,
): Promise<ArrayBuffer> {
  const isWrap = mode === CipherOrWrapMode.kWebCryptoCipherEncrypt;

  // AES-KW requires input to be a multiple of 8 bytes (64 bits)
  if (data.byteLength % 8 !== 0) {
    throw lazyDOMException(
      `AES-KW input length must be a multiple of 8 bytes, got ${data.byteLength}`,
      'OperationError',
    );
  }

  // AES-KW requires at least 16 bytes of input (128 bits)
  if (isWrap && data.byteLength < 16) {
    throw lazyDOMException(
      `AES-KW input must be at least 16 bytes, got ${data.byteLength}`,
      'OperationError',
    );
  }

  // Get cipher type based on key length
  const keyLength = (key.algorithm as { length: number }).length;
  // Use aes*-wrap for both operations (matching Node.js)
  const cipherType = `aes${keyLength}-wrap`;

  // Export key material
  const exportedKey = key.keyObject.export();
  const cipherKey = bufferLikeToArrayBuffer(exportedKey);

  // AES-KW uses a default IV as specified in RFC 3394
  const defaultWrapIV = new Uint8Array([
    0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6,
  ]);

  const factory =
    NitroModules.createHybridObject<CipherFactory>('CipherFactory');

  const cipher = factory.createCipher({
    isCipher: isWrap,
    cipherType,
    cipherKey,
    iv: defaultWrapIV.buffer, // RFC 3394 default IV for AES-KW
  });

  // Process data
  const updated = cipher.update(data);
  const final = cipher.final();

  // Concatenate results
  const result = new Uint8Array(updated.byteLength + final.byteLength);
  result.set(new Uint8Array(updated), 0);
  result.set(new Uint8Array(final), updated.byteLength);

  return result.buffer;
}

async function chaCha20Poly1305Cipher(
  mode: CipherOrWrapMode,
  key: CryptoKey,
  data: ArrayBuffer,
  algorithm: ChaCha20Poly1305Params,
): Promise<ArrayBuffer> {
  const { iv, additionalData, tagLength = 128 } = algorithm;

  // Validate IV (must be 12 bytes for ChaCha20-Poly1305)
  const ivBuffer = bufferLikeToArrayBuffer(iv);
  if (!ivBuffer || ivBuffer.byteLength !== 12) {
    throw lazyDOMException(
      'ChaCha20-Poly1305 IV must be exactly 12 bytes',
      'OperationError',
    );
  }

  // Validate tag length (only 128-bit supported)
  if (tagLength !== 128) {
    throw lazyDOMException(
      'ChaCha20-Poly1305 only supports 128-bit auth tags',
      'NotSupportedError',
    );
  }

  const tagByteLength = 16; // 128 bits = 16 bytes

  // Create cipher using existing ChaCha20-Poly1305 implementation
  const factory =
    NitroModules.createHybridObject<CipherFactory>('CipherFactory');
  const cipher = factory.createCipher({
    isCipher: mode === CipherOrWrapMode.kWebCryptoCipherEncrypt,
    cipherType: 'chacha20-poly1305',
    cipherKey: bufferLikeToArrayBuffer(key.keyObject.export()),
    iv: ivBuffer,
    authTagLen: tagByteLength,
  });

  let processData: ArrayBuffer;
  let authTag: ArrayBuffer | undefined;

  if (mode === CipherOrWrapMode.kWebCryptoCipherDecrypt) {
    // For decryption, extract auth tag from end of data
    const dataView = new Uint8Array(data);

    if (dataView.byteLength < tagByteLength) {
      throw lazyDOMException(
        'The provided data is too small.',
        'OperationError',
      );
    }

    // Split data and tag
    const ciphertextLength = dataView.byteLength - tagByteLength;
    processData = dataView.slice(0, ciphertextLength).buffer;
    authTag = dataView.slice(ciphertextLength).buffer;

    // Set auth tag for verification
    cipher.setAuthTag(authTag);
  } else {
    processData = data;
  }

  // Set additional authenticated data if provided
  if (additionalData) {
    cipher.setAAD(bufferLikeToArrayBuffer(additionalData));
  }

  // Process data
  const updated = cipher.update(processData);
  const final = cipher.final();

  if (mode === CipherOrWrapMode.kWebCryptoCipherEncrypt) {
    // For encryption, append auth tag to result
    const tag = cipher.getAuthTag();
    const result = new Uint8Array(
      updated.byteLength + final.byteLength + tag.byteLength,
    );
    result.set(new Uint8Array(updated), 0);
    result.set(new Uint8Array(final), updated.byteLength);
    result.set(new Uint8Array(tag), updated.byteLength + final.byteLength);
    return result.buffer;
  } else {
    // For decryption, just concatenate plaintext
    const result = new Uint8Array(updated.byteLength + final.byteLength);
    result.set(new Uint8Array(updated), 0);
    result.set(new Uint8Array(final), updated.byteLength);
    return result.buffer;
  }
}

async function aesGenerateKey(
  algorithm: AesKeyGenParams,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKey> {
  const { length } = algorithm;
  const name = algorithm.name;

  if (!name) {
    throw lazyDOMException('Algorithm name is required', 'OperationError');
  }

  // Validate key length
  if (![128, 192, 256].includes(length)) {
    throw lazyDOMException(
      `Invalid AES key length: ${length}. Must be 128, 192, or 256.`,
      'OperationError',
    );
  }

  // Validate usages
  const validUsages: KeyUsage[] = [
    'encrypt',
    'decrypt',
    'wrapKey',
    'unwrapKey',
  ];
  if (hasAnyNotIn(keyUsages, validUsages)) {
    throw lazyDOMException(`Unsupported key usage for ${name}`, 'SyntaxError');
  }

  // Generate random key bytes
  const keyBytes = new Uint8Array(length / 8);
  getRandomValues(keyBytes);

  // Create secret key
  const keyObject = createSecretKey(keyBytes);

  // Construct algorithm object with guaranteed name
  const keyAlgorithm: SubtleAlgorithm = { name, length };

  return new CryptoKey(keyObject, keyAlgorithm, keyUsages, extractable);
}

async function hmacGenerateKey(
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKey> {
  // Validate usages
  if (hasAnyNotIn(keyUsages, ['sign', 'verify'])) {
    throw lazyDOMException('Unsupported key usage for HMAC key', 'SyntaxError');
  }

  // Get hash algorithm
  const hash = algorithm.hash;
  if (!hash) {
    throw lazyDOMException(
      'HMAC algorithm requires a hash parameter',
      'TypeError',
    );
  }

  const hashName = normalizeHashName(hash);

  // Determine key length
  let length = algorithm.length;
  if (length === undefined) {
    // Use hash output length as default key length
    switch (hashName) {
      case 'SHA-1':
        length = 160;
        break;
      case 'SHA-256':
        length = 256;
        break;
      case 'SHA-384':
        length = 384;
        break;
      case 'SHA-512':
        length = 512;
        break;
      default:
        length = 256; // Default to 256 bits
    }
  }

  if (length === 0) {
    throw lazyDOMException(
      'Zero-length key is not supported',
      'OperationError',
    );
  }

  // Generate random key bytes
  const keyBytes = new Uint8Array(Math.ceil(length / 8));
  getRandomValues(keyBytes);

  // Create secret key
  const keyObject = createSecretKey(keyBytes);

  // Construct algorithm object with hash normalized to { name: string } format per WebCrypto spec
  const webCryptoHashName = normalizeHashName(hash, HashContext.WebCrypto);
  const keyAlgorithm: SubtleAlgorithm = {
    name: 'HMAC',
    hash: { name: webCryptoHashName },
    length,
  };

  return new CryptoKey(keyObject, keyAlgorithm, keyUsages, extractable);
}

async function kmacGenerateKey(
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKey> {
  const { name } = algorithm;

  if (hasAnyNotIn(keyUsages, ['sign', 'verify'])) {
    throw lazyDOMException(
      `Unsupported key usage for ${name} key`,
      'SyntaxError',
    );
  }

  const defaultLength = name === 'KMAC128' ? 128 : 256;
  const length = algorithm.length ?? defaultLength;

  if (length === 0) {
    throw lazyDOMException(
      'Zero-length key is not supported',
      'OperationError',
    );
  }

  const keyBytes = new Uint8Array(Math.ceil(length / 8));
  getRandomValues(keyBytes);

  const keyObject = createSecretKey(keyBytes);

  const keyAlgorithm: SubtleAlgorithm = { name: name as AnyAlgorithm, length };

  return new CryptoKey(keyObject, keyAlgorithm, keyUsages, extractable);
}

function kmacSignVerify(
  key: CryptoKey,
  data: BufferLike,
  algorithm: SubtleAlgorithm,
  signature?: BufferLike,
): ArrayBuffer | boolean {
  const { name } = algorithm;

  const defaultLength = name === 'KMAC128' ? 256 : 512;
  const outputLengthBits = algorithm.length ?? defaultLength;

  if (outputLengthBits % 8 !== 0) {
    throw lazyDOMException(
      'KMAC output length must be a multiple of 8',
      'OperationError',
    );
  }

  const outputLengthBytes = outputLengthBits / 8;

  const keyData = key.keyObject.export();

  const kmac = NitroModules.createHybridObject<Kmac>('Kmac');

  let customizationBuffer: ArrayBuffer | undefined;
  if (algorithm.customization !== undefined) {
    customizationBuffer = bufferLikeToArrayBuffer(algorithm.customization);
  }

  kmac.createKmac(
    name,
    bufferLikeToArrayBuffer(keyData),
    outputLengthBytes,
    customizationBuffer,
  );
  kmac.update(bufferLikeToArrayBuffer(data));
  const computed = kmac.digest();

  if (signature === undefined) {
    return computed;
  }

  const sigBuffer = bufferLikeToArrayBuffer(signature);
  if (computed.byteLength !== sigBuffer.byteLength) {
    return false;
  }

  return timingSafeEqual(new Uint8Array(computed), new Uint8Array(sigBuffer));
}

async function kmacImportKey(
  algorithm: SubtleAlgorithm,
  format: ImportFormat,
  data: BufferLike | JWK,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKey> {
  const { name } = algorithm;

  let keyObject: KeyObject;

  if (format === 'jwk') {
    const jwk = data as JWK;

    if (!jwk || typeof jwk !== 'object') {
      throw lazyDOMException('Invalid keyData', 'DataError');
    }
    if (jwk.kty !== 'oct') {
      throw lazyDOMException('Invalid JWK "kty" Parameter', 'DataError');
    }
    validateJwkStructure(jwk, extractable, keyUsages, 'sig');

    const expectedAlg = name === 'KMAC128' ? 'K128' : 'K256';
    if (jwk.alg !== undefined && jwk.alg !== expectedAlg) {
      throw lazyDOMException(
        'JWK "alg" Parameter and algorithm name mismatch',
        'DataError',
      );
    }

    if (hasAnyNotIn(keyUsages, ['sign', 'verify'])) {
      throw lazyDOMException(
        `Unsupported key usage for ${name} key`,
        'SyntaxError',
      );
    }

    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    let keyType: KeyType | undefined;
    try {
      keyType = handle.initJwk(jwk, undefined);
    } catch (err) {
      throw lazyDOMException('Invalid keyData', {
        name: 'DataError',
        cause: err,
      });
    }
    if (keyType === undefined || keyType !== 0) {
      throw lazyDOMException('Invalid keyData', 'DataError');
    }

    keyObject = new SecretKeyObject(handle);
  } else if (format === 'raw-secret') {
    // KMAC accepts only the disambiguated 'raw-secret' form (Node mac.js:141-145
    // returns undefined for plain 'raw' when not HMAC).
    if (hasAnyNotIn(keyUsages, ['sign', 'verify'])) {
      throw lazyDOMException(
        `Unsupported key usage for ${name} key`,
        'SyntaxError',
      );
    }
    keyObject = createSecretKey(data as BinaryLike);
  } else {
    throw lazyDOMException(
      `Unable to import ${name} key with format ${format}`,
      'NotSupportedError',
    );
  }

  const exported = keyObject.export();
  const keyLength = exported.byteLength * 8;

  if (keyLength === 0) {
    throw lazyDOMException('Zero-length key is not supported', 'DataError');
  }

  if (algorithm.length !== undefined && algorithm.length !== keyLength) {
    throw lazyDOMException('Invalid key length', 'DataError');
  }

  const keyAlgorithm: SubtleAlgorithm = {
    name: name as AnyAlgorithm,
    length: keyLength,
  };

  return new CryptoKey(keyObject, keyAlgorithm, keyUsages, extractable);
}

function rsaImportKey(
  format: ImportFormat,
  data: BufferLike | JWK,
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): CryptoKey {
  const { name } = algorithm;

  let checkSet: KeyUsage[];
  switch (name) {
    case 'RSASSA-PKCS1-v1_5':
    case 'RSA-PSS':
      checkSet = ['sign', 'verify'];
      break;
    case 'RSA-OAEP':
      checkSet = ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'];
      break;
    default:
      throw new Error(`Unsupported RSA algorithm: ${name}`);
  }
  const checkUsages = (): void => {
    if (hasAnyNotIn(keyUsages, checkSet)) {
      throw lazyDOMException(
        `Unsupported key usage for ${name} key`,
        'SyntaxError',
      );
    }
  };

  let keyObject: KeyObject;

  if (format === 'jwk') {
    const jwk = data as JWK;

    if (!jwk || typeof jwk !== 'object') {
      throw lazyDOMException('Invalid keyData', 'DataError');
    }
    if (jwk.kty !== 'RSA') {
      throw lazyDOMException('Invalid JWK "kty" Parameter', 'DataError');
    }
    const expectedUse = name === 'RSA-OAEP' ? 'enc' : 'sig';
    validateJwkStructure(jwk, extractable, keyUsages, expectedUse);
    checkUsages();

    if (jwk.alg !== undefined) {
      let jwkContext: HashContext;
      switch (name) {
        case 'RSASSA-PKCS1-v1_5':
          jwkContext = HashContext.JwkRsa;
          break;
        case 'RSA-PSS':
          jwkContext = HashContext.JwkRsaPss;
          break;
        default:
          jwkContext = HashContext.JwkRsaOaep;
      }
      const expectedAlg = normalizeHashName(algorithm.hash, jwkContext);
      if (jwk.alg !== expectedAlg) {
        throw lazyDOMException(
          'JWK "alg" does not match the requested algorithm',
          'DataError',
        );
      }
    }

    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    let keyType: KeyType | undefined;
    try {
      keyType = handle.initJwk(jwk, undefined);
    } catch (err) {
      throw lazyDOMException('Invalid keyData', {
        name: 'DataError',
        cause: err,
      });
    }
    if (keyType === undefined) {
      throw lazyDOMException('Invalid keyData', 'DataError');
    }

    if (keyType === KeyType.PUBLIC) {
      keyObject = new PublicKeyObject(handle);
    } else if (keyType === KeyType.PRIVATE) {
      keyObject = new PrivateKeyObject(handle);
    } else {
      throw lazyDOMException('Invalid keyData', 'DataError');
    }
  } else if (format === 'spki') {
    checkUsages();
    const keyData = bufferLikeToArrayBuffer(data as BufferLike);
    keyObject = KeyObject.createKeyObject(
      'public',
      keyData,
      KFormatType.DER,
      KeyEncoding.SPKI,
    );
  } else if (format === 'pkcs8') {
    checkUsages();
    const keyData = bufferLikeToArrayBuffer(data as BufferLike);
    keyObject = KeyObject.createKeyObject(
      'private',
      keyData,
      KFormatType.DER,
      KeyEncoding.PKCS8,
    );
  } else {
    throw lazyDOMException(
      `Unsupported format for ${name} import: ${format}`,
      'NotSupportedError',
    );
  }

  // Get the modulus length from the key and add it to the algorithm
  const keyDetails = (keyObject as PublicKeyObject | PrivateKeyObject)
    .asymmetricKeyDetails;

  // Convert publicExponent number to big-endian byte array
  let publicExponentBytes: Uint8Array | undefined;
  if (keyDetails?.publicExponent) {
    const exp = keyDetails.publicExponent;
    // Convert number to big-endian bytes
    const bytes: number[] = [];
    let value = exp;
    while (value > 0) {
      bytes.unshift(value & 0xff);
      value = Math.floor(value / 256);
    }
    publicExponentBytes = new Uint8Array(bytes.length > 0 ? bytes : [0]);
  }

  // Normalize hash to { name: string } format per WebCrypto spec
  const hashName = normalizeHashName(algorithm.hash, HashContext.WebCrypto);
  const normalizedHash = { name: hashName };

  const algorithmWithDetails = {
    ...algorithm,
    modulusLength: keyDetails?.modulusLength,
    publicExponent: publicExponentBytes,
    hash: normalizedHash,
  };

  return new CryptoKey(keyObject, algorithmWithDetails, keyUsages, extractable);
}

async function hmacImportKey(
  algorithm: SubtleAlgorithm,
  format: ImportFormat,
  data: BufferLike | JWK,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKey> {
  const checkUsages = (): void => {
    if (hasAnyNotIn(keyUsages, ['sign', 'verify'])) {
      throw new Error('Unsupported key usage for an HMAC key');
    }
  };

  let keyObject: KeyObject;

  if (format === 'jwk') {
    const jwk = data as JWK;

    if (!jwk || typeof jwk !== 'object') {
      throw new Error('Invalid keyData');
    }
    if (jwk.kty !== 'oct') {
      throw new Error('Invalid JWK format for HMAC key');
    }
    validateJwkStructure(jwk, extractable, keyUsages, 'sig');
    checkUsages();

    if (algorithm.length !== undefined) {
      if (!jwk.k) {
        throw new Error('JWK missing key data');
      }
      const decoded = SBuffer.from(jwk.k, 'base64');
      const keyBitLength = decoded.length * 8;
      if (algorithm.length === 0) {
        throw new Error('Zero-length key is not supported');
      }
      if (algorithm.length !== keyBitLength) {
        throw new Error('Invalid key length');
      }
    }

    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    let keyType: KeyType | undefined;
    try {
      keyType = handle.initJwk(jwk, undefined);
    } catch (err) {
      throw lazyDOMException('Invalid keyData', {
        name: 'DataError',
        cause: err,
      });
    }
    if (keyType === undefined || keyType !== 0) {
      throw lazyDOMException('Invalid keyData', 'DataError');
    }

    keyObject = new SecretKeyObject(handle);
  } else if (format === 'raw' || format === 'raw-secret') {
    // HMAC accepts both 'raw' and 'raw-secret' (Node mac.js:141-145).
    checkUsages();
    keyObject = createSecretKey(data as BinaryLike);
  } else {
    throw lazyDOMException(
      `Unable to import HMAC key with format ${format}`,
      'NotSupportedError',
    );
  }

  // Normalize hash to { name: string } format per WebCrypto spec
  const hashName = normalizeHashName(algorithm.hash, HashContext.WebCrypto);
  const normalizedAlgorithm: SubtleAlgorithm = {
    ...algorithm,
    name: 'HMAC',
    hash: { name: hashName },
  };

  return new CryptoKey(keyObject, normalizedAlgorithm, keyUsages, extractable);
}

async function aesImportKey(
  algorithm: SubtleAlgorithm,
  format: ImportFormat,
  data: BufferLike | JWK,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKey> {
  const { name, length } = algorithm;

  const validUsages: KeyUsage[] = [
    'encrypt',
    'decrypt',
    'wrapKey',
    'unwrapKey',
  ];
  const checkUsages = (): void => {
    if (hasAnyNotIn(keyUsages, validUsages)) {
      throw new Error(`Unsupported key usage for ${name}`);
    }
  };

  // AES-OCB and ChaCha20-Poly1305 require the disambiguated 'raw-secret' form
  // and reject 'raw' (Node aes.js:243-249, chacha20_poly1305.js:104-134).
  // Other AES variants accept both 'raw' and 'raw-secret'.
  const requiresRawSecret = name === 'AES-OCB' || name === 'ChaCha20-Poly1305';
  const acceptsRaw =
    format === 'raw-secret' || (format === 'raw' && !requiresRawSecret);

  let keyObject: KeyObject;
  let actualLength: number;

  if (format === 'jwk') {
    const jwk = data as JWK;

    if (jwk.kty !== 'oct') {
      throw new Error('Invalid JWK format for AES key');
    }
    validateJwkStructure(jwk, extractable, keyUsages, 'enc');
    checkUsages();

    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    let keyType: KeyType | undefined;
    try {
      keyType = handle.initJwk(jwk, undefined);
    } catch (err) {
      throw lazyDOMException('Invalid keyData', {
        name: 'DataError',
        cause: err,
      });
    }
    if (keyType === undefined || keyType !== 0) {
      throw lazyDOMException('Invalid keyData', 'DataError');
    }

    keyObject = new SecretKeyObject(handle);

    const exported = keyObject.export();
    actualLength = exported.byteLength * 8;
  } else if (acceptsRaw) {
    checkUsages();
    const keyData = bufferLikeToArrayBuffer(data as BufferLike);
    actualLength = keyData.byteLength * 8;

    if (name === 'ChaCha20-Poly1305') {
      if (actualLength !== 256) {
        throw lazyDOMException(
          'Invalid ChaCha20-Poly1305 key length',
          'DataError',
        );
      }
    } else if (![128, 192, 256].includes(actualLength)) {
      throw new Error('Invalid AES key length');
    }

    keyObject = createSecretKey(keyData);
  } else {
    throw lazyDOMException(
      `Unable to import ${name} key with format ${format}`,
      'NotSupportedError',
    );
  }

  // Validate length if specified
  if (length !== undefined && length !== actualLength) {
    throw new Error(
      `Key length mismatch: expected ${length}, got ${actualLength}`,
    );
  }

  return new CryptoKey(
    keyObject,
    { name, length: actualLength },
    keyUsages,
    extractable,
  );
}

function edImportKey(
  format: ImportFormat,
  data: BufferLike | JWK,
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): CryptoKey {
  const { name } = algorithm;

  const isX = name === 'X25519' || name === 'X448';
  const allowedUsages: KeyUsage[] = isX
    ? ['deriveKey', 'deriveBits']
    : ['sign', 'verify'];
  const checkUsages = (): void => {
    if (hasAnyNotIn(keyUsages, allowedUsages)) {
      throw lazyDOMException(
        `Unsupported key usage for ${name} key`,
        'SyntaxError',
      );
    }
  };

  let keyObject: KeyObject;

  if (format === 'spki') {
    checkUsages();
    const keyData = bufferLikeToArrayBuffer(data as BufferLike);
    keyObject = KeyObject.createKeyObject(
      'public',
      keyData,
      KFormatType.DER,
      KeyEncoding.SPKI,
    );
  } else if (format === 'pkcs8') {
    checkUsages();
    const keyData = bufferLikeToArrayBuffer(data as BufferLike);
    keyObject = KeyObject.createKeyObject(
      'private',
      keyData,
      KFormatType.DER,
      KeyEncoding.PKCS8,
    );
  } else if (format === 'raw') {
    checkUsages();
    const keyData = bufferLikeToArrayBuffer(data as BufferLike);
    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    handle.init(1, keyData);
    keyObject = new PublicKeyObject(handle);
  } else if (format === 'jwk') {
    const jwkData = data as JWK;
    if (!jwkData || typeof jwkData !== 'object') {
      throw lazyDOMException('Invalid keyData', 'DataError');
    }
    if (jwkData.kty !== 'OKP') {
      throw lazyDOMException('Invalid JWK "kty" Parameter', 'DataError');
    }
    const expectedUse = isX ? 'enc' : 'sig';
    validateJwkStructure(jwkData, extractable, keyUsages, expectedUse);

    if (jwkData.crv !== name) {
      throw lazyDOMException(
        'JWK "crv" Parameter and algorithm name mismatch',
        'DataError',
      );
    }

    if (!isX && jwkData.alg !== undefined) {
      if (jwkData.alg !== name && jwkData.alg !== 'EdDSA') {
        throw lazyDOMException(
          'JWK "alg" does not match the requested algorithm',
          'DataError',
        );
      }
    }

    checkUsages();
    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    let keyType: KeyType | undefined;
    try {
      keyType = handle.initJwk(jwkData);
    } catch (err) {
      throw lazyDOMException('Invalid JWK data', {
        name: 'DataError',
        cause: err,
      });
    }
    if (keyType === undefined) {
      throw lazyDOMException('Invalid JWK data', 'DataError');
    }
    if (keyType === KeyType.PRIVATE) {
      keyObject = new PrivateKeyObject(handle);
    } else {
      keyObject = new PublicKeyObject(handle);
    }
  } else {
    throw lazyDOMException(
      `Unsupported format for ${name} import: ${format}`,
      'NotSupportedError',
    );
  }

  return new CryptoKey(keyObject, { name }, keyUsages, extractable);
}

// Lengths (in bytes) of seedless ML-DSA / ML-KEM PKCS#8 encodings. A PKCS#8
// blob of exactly this length contains only the expanded private key with no
// seed; Node rejects these to keep cross-implementation interop intact.
// Refs: node lib/internal/crypto/ml_dsa.js (mlDsaImportKey, pkcs8 case)
//       node lib/internal/crypto/ml_kem.js (mlKemImportKey, pkcs8 case)
export const PQC_SEEDLESS_PKCS8_LENGTHS: Readonly<Record<string, number>> = {
  'ML-DSA-44': 2588,
  'ML-DSA-65': 4060,
  'ML-DSA-87': 4924,
  'ML-KEM-512': 1660,
  'ML-KEM-768': 2428,
  'ML-KEM-1024': 3196,
};

// Map from PQC algorithm name to display family. Used to render the
// import-rejection error message in the same form Node emits.
const PQC_FAMILY: Readonly<Record<string, 'ML-DSA' | 'ML-KEM'>> = {
  'ML-DSA-44': 'ML-DSA',
  'ML-DSA-65': 'ML-DSA',
  'ML-DSA-87': 'ML-DSA',
  'ML-KEM-512': 'ML-KEM',
  'ML-KEM-768': 'ML-KEM',
  'ML-KEM-1024': 'ML-KEM',
};

function pqcImportKeyObject(
  format: ImportFormat,
  data: BufferLike | JWK,
  name: string,
): { keyObject: KeyObject; isPublic: boolean } {
  if (format === 'spki') {
    return {
      keyObject: KeyObject.createKeyObject(
        'public',
        bufferLikeToArrayBuffer(data as BufferLike),
        KFormatType.DER,
        KeyEncoding.SPKI,
      ),
      isPublic: true,
    };
  } else if (format === 'pkcs8') {
    const ab = bufferLikeToArrayBuffer(data as BufferLike);
    const family = PQC_FAMILY[name];
    if (
      family !== undefined &&
      ab.byteLength === PQC_SEEDLESS_PKCS8_LENGTHS[name]
    ) {
      throw lazyDOMException(
        `Importing an ${family} PKCS#8 key without a seed is not supported`,
        'NotSupportedError',
      );
    }
    return {
      keyObject: KeyObject.createKeyObject(
        'private',
        ab,
        KFormatType.DER,
        KeyEncoding.PKCS8,
      ),
      isPublic: false,
    };
  } else if (format === 'raw-public') {
    // ML-DSA / ML-KEM reject plain 'raw' — only 'raw-public' is accepted for
    // public-key import (Node webcrypto.js:493-499, 506-511).
    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    if (
      !handle.initPqcRaw(
        name,
        bufferLikeToArrayBuffer(data as BufferLike),
        true,
      )
    ) {
      throw lazyDOMException(
        `Failed to import ${name} raw public key`,
        'DataError',
      );
    }
    return { keyObject: new PublicKeyObject(handle), isPublic: true };
  } else if (format === 'raw-seed') {
    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    if (
      !handle.initPqcRaw(
        name,
        bufferLikeToArrayBuffer(data as BufferLike),
        false,
      )
    ) {
      throw lazyDOMException(`Failed to import ${name} raw seed`, 'DataError');
    }
    return { keyObject: new PrivateKeyObject(handle), isPublic: false };
  } else if (format === 'jwk') {
    const jwkData = data as JWK;
    const isPublic = jwkData.priv === undefined;
    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    let keyType: KeyType | undefined;
    try {
      keyType = handle.initJwk(jwkData);
    } catch (err) {
      throw lazyDOMException('Invalid JWK data', {
        name: 'DataError',
        cause: err,
      });
    }
    if (keyType === undefined) {
      throw lazyDOMException('Invalid JWK data', 'DataError');
    }
    return {
      keyObject: isPublic
        ? new PublicKeyObject(handle)
        : new PrivateKeyObject(handle),
      isPublic,
    };
  }
  throw lazyDOMException(
    `Unsupported format for ${name} import: ${format}`,
    'NotSupportedError',
  );
}

// Per WebCrypto AKP JWK rules, public-vs-private is determined by the presence
// of `priv`. For binary formats it follows from the format itself.
function pqcIsPublicImport(
  format: ImportFormat,
  data: BufferLike | JWK,
): boolean {
  if (format === 'jwk') {
    return (
      typeof data === 'object' &&
      data !== null &&
      (data as JWK).priv === undefined
    );
  }
  return format === 'spki' || format === 'raw-public';
}

function validatePqcJwk(
  data: BufferLike | JWK,
  name: string,
  extractable: boolean,
  keyUsages: KeyUsage[],
  expectedUse: 'sig' | 'enc',
): void {
  if (typeof data !== 'object' || data === null) {
    throw lazyDOMException('Invalid keyData', 'DataError');
  }
  const jwk = data as JWK;
  if (jwk.kty !== 'AKP') {
    throw lazyDOMException('Invalid JWK "kty" Parameter', 'DataError');
  }
  validateJwkStructure(jwk, extractable, keyUsages, expectedUse);
  if (jwk.alg !== name) {
    throw lazyDOMException(
      'JWK "alg" Parameter and algorithm name mismatch',
      'DataError',
    );
  }
}

// Validates that `format` is one of the formats PQC algorithms accept; rejects
// plain 'raw' early so the format error wins over usage-based errors.
function validatePqcFormat(format: ImportFormat, name: string): void {
  if (
    format !== 'spki' &&
    format !== 'pkcs8' &&
    format !== 'raw-public' &&
    format !== 'raw-seed' &&
    format !== 'jwk'
  ) {
    throw lazyDOMException(
      `Unsupported format for ${name} import: ${format}`,
      'NotSupportedError',
    );
  }
}

function mldsaImportKey(
  format: ImportFormat,
  data: BufferLike | JWK,
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): CryptoKey {
  const { name } = algorithm;
  validatePqcFormat(format, name);
  if (format === 'jwk') {
    validatePqcJwk(data, name, extractable, keyUsages, 'sig');
  }
  const isPublic = pqcIsPublicImport(format, data);
  if (hasAnyNotIn(keyUsages, isPublic ? ['verify'] : ['sign'])) {
    throw lazyDOMException(
      `Unsupported key usage for ${name} key`,
      'SyntaxError',
    );
  }
  const { keyObject } = pqcImportKeyObject(format, data, name);
  return new CryptoKey(keyObject, { name }, keyUsages, extractable);
}

function mlkemImportKey(
  format: ImportFormat,
  data: BufferLike | JWK,
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): CryptoKey {
  const { name } = algorithm;
  validatePqcFormat(format, name);
  if (format === 'jwk') {
    validatePqcJwk(data, name, extractable, keyUsages, 'enc');
  }
  const isPublic = pqcIsPublicImport(format, data);
  const allowedUsages: KeyUsage[] = isPublic
    ? ['encapsulateBits', 'encapsulateKey']
    : ['decapsulateBits', 'decapsulateKey'];
  if (hasAnyNotIn(keyUsages, allowedUsages)) {
    throw lazyDOMException(
      `Unsupported key usage for ${name} key`,
      'SyntaxError',
    );
  }
  const { keyObject } = pqcImportKeyObject(format, data, name);
  return new CryptoKey(keyObject, { name }, keyUsages, extractable);
}

const exportKeySpki = async (
  key: CryptoKey,
): Promise<ArrayBuffer | unknown> => {
  switch (key.algorithm.name) {
    case 'RSASSA-PKCS1-v1_5':
    // Fall through
    case 'RSA-PSS':
    // Fall through
    case 'RSA-OAEP':
      if (key.type === 'public') {
        return rsaExportKey(key, KWebCryptoKeyFormat.kWebCryptoKeyFormatSPKI);
      }
      break;
    case 'ECDSA':
    // Fall through
    case 'ECDH':
      if (key.type === 'public') {
        return ecExportKey(key, KWebCryptoKeyFormat.kWebCryptoKeyFormatSPKI);
      }
      break;
    case 'Ed25519':
    // Fall through
    case 'Ed448':
    // Fall through
    case 'X25519':
    // Fall through
    case 'X448':
      if (key.type === 'public') {
        // Export Ed/X key in SPKI DER format
        return bufferLikeToArrayBuffer(
          key.keyObject.handle.exportKey(KFormatType.DER, KeyEncoding.SPKI),
        );
      }
      break;
    case 'ML-DSA-44':
    // Fall through
    case 'ML-DSA-65':
    // Fall through
    case 'ML-DSA-87':
      if (key.type === 'public') {
        // Export ML-DSA key in SPKI DER format
        return bufferLikeToArrayBuffer(
          key.keyObject.handle.exportKey(KFormatType.DER, KeyEncoding.SPKI),
        );
      }
      break;
    case 'ML-KEM-512':
    // Fall through
    case 'ML-KEM-768':
    // Fall through
    case 'ML-KEM-1024':
      if (key.type === 'public') {
        return bufferLikeToArrayBuffer(
          key.keyObject.handle.exportKey(KFormatType.DER, KeyEncoding.SPKI),
        );
      }
      break;
  }

  throw new Error(
    `Unable to export a spki ${key.algorithm.name} ${key.type} key`,
  );
};

const exportKeyPkcs8 = async (
  key: CryptoKey,
): Promise<ArrayBuffer | unknown> => {
  switch (key.algorithm.name) {
    case 'RSASSA-PKCS1-v1_5':
    // Fall through
    case 'RSA-PSS':
    // Fall through
    case 'RSA-OAEP':
      if (key.type === 'private') {
        return rsaExportKey(key, KWebCryptoKeyFormat.kWebCryptoKeyFormatPKCS8);
      }
      break;
    case 'ECDSA':
    // Fall through
    case 'ECDH':
      if (key.type === 'private') {
        return ecExportKey(key, KWebCryptoKeyFormat.kWebCryptoKeyFormatPKCS8);
      }
      break;
    case 'Ed25519':
    // Fall through
    case 'Ed448':
    // Fall through
    case 'X25519':
    // Fall through
    case 'X448':
      if (key.type === 'private') {
        // Export Ed/X key in PKCS8 DER format
        return bufferLikeToArrayBuffer(
          key.keyObject.handle.exportKey(KFormatType.DER, KeyEncoding.PKCS8),
        );
      }
      break;
    case 'ML-DSA-44':
    // Fall through
    case 'ML-DSA-65':
    // Fall through
    case 'ML-DSA-87':
    // Fall through
    case 'ML-KEM-512':
    // Fall through
    case 'ML-KEM-768':
    // Fall through
    case 'ML-KEM-1024':
      if (key.type === 'private') {
        const ab = bufferLikeToArrayBuffer(
          key.keyObject.handle.exportKey(KFormatType.DER, KeyEncoding.PKCS8),
        );
        // 22 bytes of PKCS#8 ASN.1 + seed (32 ML-DSA, 64 ML-KEM). Guards
        // against a seedless KeyObject that was wrapped via toCryptoKey.
        const expected = key.algorithm.name.startsWith('ML-DSA') ? 54 : 86;
        if (ab.byteLength !== expected) {
          throw lazyDOMException(
            'The operation failed for an operation-specific reason',
            'OperationError',
          );
        }
        return ab;
      }
      break;
  }

  throw new Error(
    `Unable to export a pkcs8 ${key.algorithm.name} ${key.type} key`,
  );
};

// Mirrors Node's export key matrix (lib/internal/crypto/webcrypto.js
// exportKeyRawSecret / exportKeyRawPublic, lines 472-563):
//
//   raw         — AES-CTR/CBC/GCM/KW + HMAC (secret); ECDSA/ECDH/Ed/X (public)
//   raw-secret  — AES-CTR/CBC/GCM/KW + HMAC + AES-OCB + KMAC + ChaCha20-Poly1305
//   raw-public  — ECDSA/ECDH + Ed/X + ML-DSA + ML-KEM (public)
const exportKeyRaw = (
  key: CryptoKey,
  format: 'raw' | 'raw-secret' | 'raw-public',
): ArrayBuffer => {
  const name = key.algorithm.name;
  const isPublic = key.type === 'public';
  const isSecret = key.type === 'secret';

  const exportSecret = (): ArrayBuffer => {
    const exported = key.keyObject.export();
    return exported.buffer.slice(
      exported.byteOffset,
      exported.byteOffset + exported.byteLength,
    ) as ArrayBuffer;
  };
  const exportRawPublic = (): ArrayBuffer =>
    bufferLikeToArrayBuffer(key.keyObject.handle.exportKey());

  const fail = (): never => {
    throw lazyDOMException(
      `Unable to export ${name} ${key.type} key using ${format} format`,
      'NotSupportedError',
    );
  };

  // Symmetric: AES-CTR/CBC/GCM/KW and HMAC accept both 'raw' and 'raw-secret';
  // AES-OCB / KMAC* / ChaCha20-Poly1305 only 'raw-secret'.
  switch (name) {
    case 'AES-CTR':
    case 'AES-CBC':
    case 'AES-GCM':
    case 'AES-KW':
    case 'HMAC':
      if (!isSecret) return fail();
      if (format === 'raw' || format === 'raw-secret') return exportSecret();
      return fail();
    case 'AES-OCB':
    case 'KMAC128':
    case 'KMAC256':
    case 'ChaCha20-Poly1305':
      if (!isSecret) return fail();
      if (format === 'raw-secret') return exportSecret();
      return fail();
    case 'ECDSA':
    case 'ECDH':
      if (!isPublic) return fail();
      if (format === 'raw' || format === 'raw-public') {
        return ecExportKey(key, KWebCryptoKeyFormat.kWebCryptoKeyFormatRaw);
      }
      return fail();
    case 'Ed25519':
    case 'Ed448':
    case 'X25519':
    case 'X448':
      if (!isPublic) return fail();
      if (format === 'raw' || format === 'raw-public') return exportRawPublic();
      return fail();
    case 'ML-DSA-44':
    case 'ML-DSA-65':
    case 'ML-DSA-87':
    case 'ML-KEM-512':
    case 'ML-KEM-768':
    case 'ML-KEM-1024':
      // ML-DSA / ML-KEM keys do not recognize plain 'raw' (Node webcrypto.js
      // lines 488-510).
      if (!isPublic) return fail();
      if (format === 'raw-public') return exportRawPublic();
      return fail();
  }

  return fail();
};

const exportKeyJWK = (key: CryptoKey): ArrayBuffer | unknown => {
  const jwk = key.keyObject.handle.exportJwk(
    {
      key_ops: [...key.usages],
      ext: key.extractable,
    },
    true,
  );
  switch (key.algorithm.name) {
    case 'RSASSA-PKCS1-v1_5':
      jwk.alg = normalizeHashName(key.algorithm.hash, HashContext.JwkRsa);
      return jwk;
    case 'RSA-PSS':
      jwk.alg = normalizeHashName(key.algorithm.hash, HashContext.JwkRsaPss);
      return jwk;
    case 'RSA-OAEP':
      jwk.alg = normalizeHashName(key.algorithm.hash, HashContext.JwkRsaOaep);
      return jwk;
    case 'HMAC':
      jwk.alg = normalizeHashName(key.algorithm.hash, HashContext.JwkHmac);
      return jwk;
    case 'KMAC128':
      jwk.alg = 'K128';
      return jwk;
    case 'KMAC256':
      jwk.alg = 'K256';
      return jwk;
    case 'ECDSA':
    // Fall through
    case 'ECDH':
      jwk.crv ||= key.algorithm.namedCurve;
      return jwk;
    case 'Ed25519':
    // Fall through
    case 'Ed448':
    // Fall through
    case 'X25519':
    // Fall through
    case 'X448':
      return jwk;
    case 'ML-DSA-44':
    // Fall through
    case 'ML-DSA-65':
    // Fall through
    case 'ML-DSA-87':
    // Fall through
    case 'ML-KEM-512':
    // Fall through
    case 'ML-KEM-768':
    // Fall through
    case 'ML-KEM-1024':
      return jwk;
    case 'AES-CTR':
    // Fall through
    case 'AES-CBC':
    // Fall through
    case 'AES-GCM':
    // Fall through
    case 'AES-KW':
    // Fall through
    case 'AES-OCB':
    // Fall through
    case 'ChaCha20-Poly1305':
      if (key.algorithm.length === undefined) {
        throw lazyDOMException(
          `Algorithm ${key.algorithm.name} missing required length property`,
          'InvalidAccessError',
        );
      }
      jwk.alg = getAlgorithmName(key.algorithm.name, key.algorithm.length);
      return jwk;
    default:
    // Fall through
  }

  throw lazyDOMException(
    `JWK export not yet supported: ${key.algorithm.name}`,
    'NotSupportedError',
  );
};

// PBKDF2 import. Mirrors Node's importGenericSecretKey ordering
// (keys.js:945-971): extractable → usage → format → length. Callers pre-alias
// 'raw-secret' / 'raw-public' to 'raw' via aliasKeyFormat
// (webcrypto.js:798-808).
const pbkdf2ImportKey = async (
  { name, length }: SubtleAlgorithm,
  format: ImportFormat,
  keyData: BufferLike | BinaryLike,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKey> => {
  if (extractable) {
    throw lazyDOMException(`${name} keys are not extractable`, 'SyntaxError');
  }
  if (hasAnyNotIn(keyUsages, ['deriveKey', 'deriveBits'])) {
    throw lazyDOMException(
      `Unsupported key usage for a ${name} key`,
      'SyntaxError',
    );
  }
  if (format !== 'raw') {
    throw lazyDOMException(
      `Unable to import ${name} key with format ${format}`,
      'NotSupportedError',
    );
  }

  const checkLength =
    typeof keyData === 'string' || SBuffer.isBuffer(keyData)
      ? keyData.length * 8
      : keyData.byteLength * 8;
  if (length !== undefined && length !== checkLength) {
    throw lazyDOMException('Invalid key length', 'DataError');
  }

  const keyObject = createSecretKey(keyData as BinaryLike);
  return new CryptoKey(keyObject, { name }, keyUsages, false);
};

// Argon2 import. Node gates the format at the dispatcher level — only
// 'raw-secret' enters importGenericSecretKey (webcrypto.js:813-822). To match
// that, format is the first check here; remaining ordering matches Node's
// importGenericSecretKey.
const argon2ImportKey = async (
  { name, length }: SubtleAlgorithm,
  format: ImportFormat,
  keyData: BufferLike | BinaryLike,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKey> => {
  if (format !== 'raw-secret') {
    throw lazyDOMException(
      `Unable to import ${name} key with format ${format}`,
      'NotSupportedError',
    );
  }
  if (extractable) {
    throw lazyDOMException(`${name} keys are not extractable`, 'SyntaxError');
  }
  if (hasAnyNotIn(keyUsages, ['deriveKey', 'deriveBits'])) {
    throw lazyDOMException(
      `Unsupported key usage for a ${name} key`,
      'SyntaxError',
    );
  }

  const checkLength =
    typeof keyData === 'string' || SBuffer.isBuffer(keyData)
      ? keyData.length * 8
      : keyData.byteLength * 8;
  if (length !== undefined && length !== checkLength) {
    throw lazyDOMException('Invalid key length', 'DataError');
  }

  const keyObject = createSecretKey(keyData as BinaryLike);
  return new CryptoKey(keyObject, { name }, keyUsages, false);
};

const hkdfImportKey = async (
  format: ImportFormat,
  keyData: BufferLike | BinaryLike,
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKey> => {
  const { name } = algorithm;
  // WebCrypto §28.7.6: HKDF keys are never extractable. The previous
  // implementation passed `extractable` through verbatim, allowing callers
  // to round-trip the input keying material via `exportKey` — defeating
  // the whole point of the deriveBits-only usage.
  if (extractable) {
    throw lazyDOMException(`${name} keys are not extractable`, 'SyntaxError');
  }
  if (hasAnyNotIn(keyUsages, ['deriveKey', 'deriveBits'])) {
    throw new Error(`Unsupported key usage for a ${name} key`);
  }

  switch (format) {
    case 'raw': {
      const keyObject = createSecretKey(keyData as BinaryLike);
      return new CryptoKey(keyObject, { name }, keyUsages, false);
    }
    default:
      throw new Error(`Unable to import ${name} key with format ${format}`);
  }
};

const checkCryptoKeyPairUsages = (pair: CryptoKeyPair) => {
  if (
    pair.privateKey &&
    pair.privateKey instanceof CryptoKey &&
    pair.privateKey.keyUsages &&
    pair.privateKey.keyUsages.length > 0
  ) {
    return;
  }
  throw lazyDOMException(
    'Usages cannot be empty when creating a key.',
    'SyntaxError',
  );
};

function argon2DeriveBits(
  algorithm: SubtleAlgorithm,
  baseKey: CryptoKey,
  length: number,
): ArrayBuffer {
  if (length === 0 || length % 8 !== 0) {
    throw lazyDOMException(
      'Invalid Argon2 derived key length',
      'OperationError',
    );
  }
  if (length < 32) {
    throw lazyDOMException(
      'Argon2 derived key length must be at least 32 bits',
      'OperationError',
    );
  }

  const { nonce, parallelism, memory, passes, secretValue, associatedData } =
    algorithm;
  const tagLength = length / 8;
  const message = baseKey.keyObject.export();
  const algName = algorithm.name.toLowerCase();

  const result = argon2Sync(algName, {
    message,
    nonce: nonce ?? new Uint8Array(0),
    parallelism: parallelism ?? 1,
    tagLength,
    memory: memory ?? 65536,
    passes: passes ?? 3,
    secret: secretValue,
    associatedData,
    version: algorithm.version,
  });

  return bufferLikeToArrayBuffer(result);
}

// Type guard to check if result is CryptoKeyPair
export function isCryptoKeyPair(
  result: CryptoKey | CryptoKeyPair,
): result is CryptoKeyPair {
  return 'publicKey' in result && 'privateKey' in result;
}

function hmacSignVerify(
  key: CryptoKey,
  data: BufferLike,
  signature?: BufferLike,
): ArrayBuffer | boolean {
  // Get hash algorithm from key
  const hashName = normalizeHashName(key.algorithm.hash);

  // Export the secret key material
  const keyData = key.keyObject.export();

  // Create HMAC and compute digest
  const hmac = createHmac(hashName, keyData);
  hmac.update(bufferLikeToArrayBuffer(data));
  const computed = hmac.digest();

  if (signature === undefined) {
    // Sign operation - return the HMAC as ArrayBuffer
    return computed.buffer.slice(
      computed.byteOffset,
      computed.byteOffset + computed.byteLength,
    );
  }

  const sigBuffer = bufferLikeToArrayBuffer(signature);
  const computedBuffer = computed.buffer.slice(
    computed.byteOffset,
    computed.byteOffset + computed.byteLength,
  );

  if (computedBuffer.byteLength !== sigBuffer.byteLength) {
    return false;
  }

  return timingSafeEqual(
    new Uint8Array(computedBuffer),
    new Uint8Array(sigBuffer),
  );
}

function rsaSignVerify(
  key: CryptoKey,
  data: BufferLike,
  padding: 'pkcs1' | 'pss',
  signature?: BufferLike,
  saltLength?: number,
): ArrayBuffer | boolean {
  // Get hash algorithm from key
  const hashName = normalizeHashName(key.algorithm.hash);

  // Determine RSA padding constant
  const RSA_PKCS1_PADDING = 1;
  const RSA_PKCS1_PSS_PADDING = 6;
  const paddingValue =
    padding === 'pss' ? RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING;

  if (signature === undefined) {
    // Sign operation
    const signer = createSign(hashName);
    signer.update(data);
    const sig = signer.sign({
      key: key,
      padding: paddingValue,
      saltLength,
    });
    return sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength);
  }

  // Verify operation
  const verifier = createVerify(hashName);
  verifier.update(data);
  return verifier.verify(
    {
      key: key,
      padding: paddingValue,
      saltLength,
    },
    signature,
  );
}

function edSignVerify(
  key: CryptoKey,
  data: BufferLike,
  signature?: BufferLike,
): ArrayBuffer | boolean {
  const isSign = signature === undefined;
  const expectedKeyType = isSign ? 'private' : 'public';

  if (key.type !== expectedKeyType) {
    throw lazyDOMException(
      `Key must be a ${expectedKeyType} key`,
      'InvalidAccessError',
    );
  }

  // Get curve type from algorithm name (Ed25519 or Ed448)
  const algorithmName = key.algorithm.name;
  const curveType = algorithmName.toLowerCase() as 'ed25519' | 'ed448';

  // Create Ed instance with the curve
  const ed = new Ed(curveType, {});

  // Export raw key bytes (exportKey with no format returns raw for Ed keys)
  const rawKey = key.keyObject.handle.exportKey();
  const dataBuffer = bufferLikeToArrayBuffer(data);

  if (isSign) {
    // Sign operation - use raw private key
    const sig = ed.signSync(dataBuffer, rawKey);
    return sig;
  } else {
    // Verify operation - use raw public key
    const signatureBuffer = bufferLikeToArrayBuffer(signature!);
    return ed.verifySync(signatureBuffer, dataBuffer, rawKey);
  }
}

function mldsaSignVerify(
  key: CryptoKey,
  data: BufferLike,
  signature?: BufferLike,
): ArrayBuffer | boolean {
  const isSign = signature === undefined;
  const expectedKeyType = isSign ? 'private' : 'public';

  if (key.type !== expectedKeyType) {
    throw lazyDOMException(
      `Key must be a ${expectedKeyType} key`,
      'InvalidAccessError',
    );
  }

  const dataBuffer = bufferLikeToArrayBuffer(data);

  if (isSign) {
    const signer = createSign('');
    signer.update(dataBuffer);
    const sig = signer.sign({ key: key });
    return sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength);
  } else {
    const signatureBuffer = bufferLikeToArrayBuffer(signature!);
    const verifier = createVerify('');
    verifier.update(dataBuffer);
    return verifier.verify({ key: key }, signatureBuffer);
  }
}

const signVerify = (
  algorithm: SubtleAlgorithm,
  key: CryptoKey,
  data: BufferLike,
  signature?: BufferLike,
): ArrayBuffer | boolean => {
  const usage: Operation = signature === undefined ? 'sign' : 'verify';
  algorithm = normalizeAlgorithm(algorithm, usage);

  if (!key.usages.includes(usage) || algorithm.name !== key.algorithm.name) {
    throw lazyDOMException(
      `Unable to use this key to ${usage}`,
      'InvalidAccessError',
    );
  }

  switch (algorithm.name) {
    case 'ECDSA':
      return ecdsaSignVerify(key, data, algorithm, signature);
    case 'HMAC':
      return hmacSignVerify(key, data, signature);
    case 'RSASSA-PKCS1-v1_5':
      return rsaSignVerify(key, data, 'pkcs1', signature);
    case 'RSA-PSS':
      return rsaSignVerify(key, data, 'pss', signature, algorithm.saltLength);
    case 'Ed25519':
    case 'Ed448':
      return edSignVerify(key, data, signature);
    case 'ML-DSA-44':
    case 'ML-DSA-65':
    case 'ML-DSA-87':
      return mldsaSignVerify(key, data, signature);
    case 'KMAC128':
    case 'KMAC256':
      return kmacSignVerify(key, data, algorithm, signature);
  }
  throw lazyDOMException(
    `Unrecognized algorithm name '${algorithm.name}' for '${usage}'`,
    'NotSupportedError',
  );
};

const cipherOrWrap = async (
  mode: CipherOrWrapMode,
  algorithm: EncryptDecryptParams,
  key: CryptoKey,
  data: ArrayBuffer,
  op: Operation,
): Promise<ArrayBuffer> => {
  if (
    key.algorithm.name !== algorithm.name ||
    !key.usages.includes(op as KeyUsage)
  ) {
    throw lazyDOMException(
      'The requested operation is not valid for the provided key',
      'InvalidAccessError',
    );
  }

  validateMaxBufferLength(data, 'data');

  switch (algorithm.name) {
    case 'RSA-OAEP':
      return rsaCipher(mode, key, data, algorithm);
    case 'AES-CTR':
    // Fall through
    case 'AES-CBC':
    // Fall through
    case 'AES-GCM':
    // Fall through
    case 'AES-OCB':
      return aesCipher(mode, key, data, algorithm);
    case 'AES-KW':
      return aesKwCipher(mode, key, data);
    case 'ChaCha20-Poly1305':
      return chaCha20Poly1305Cipher(
        mode,
        key,
        data,
        algorithm as ChaCha20Poly1305Params,
      );
  }
};

const SUPPORTED_ALGORITHMS: Record<string, Set<string>> = {
  encrypt: new Set([
    'RSA-OAEP',
    'AES-CTR',
    'AES-CBC',
    'AES-GCM',
    'AES-OCB',
    'ChaCha20-Poly1305',
  ]),
  decrypt: new Set([
    'RSA-OAEP',
    'AES-CTR',
    'AES-CBC',
    'AES-GCM',
    'AES-OCB',
    'ChaCha20-Poly1305',
  ]),
  sign: new Set([
    'RSASSA-PKCS1-v1_5',
    'RSA-PSS',
    'ECDSA',
    'HMAC',
    'KMAC128',
    'KMAC256',
    'Ed25519',
    'Ed448',
    'ML-DSA-44',
    'ML-DSA-65',
    'ML-DSA-87',
  ]),
  verify: new Set([
    'RSASSA-PKCS1-v1_5',
    'RSA-PSS',
    'ECDSA',
    'HMAC',
    'KMAC128',
    'KMAC256',
    'Ed25519',
    'Ed448',
    'ML-DSA-44',
    'ML-DSA-65',
    'ML-DSA-87',
  ]),
  digest: new Set([
    'SHA-1',
    'SHA-256',
    'SHA-384',
    'SHA-512',
    'SHA3-256',
    'SHA3-384',
    'SHA3-512',
    'cSHAKE128',
    'cSHAKE256',
  ]),
  generateKey: new Set([
    'RSASSA-PKCS1-v1_5',
    'RSA-PSS',
    'RSA-OAEP',
    'ECDSA',
    'ECDH',
    'Ed25519',
    'Ed448',
    'X25519',
    'X448',
    'AES-CTR',
    'AES-CBC',
    'AES-GCM',
    'AES-KW',
    'AES-OCB',
    'ChaCha20-Poly1305',
    'HMAC',
    'KMAC128',
    'KMAC256',
    'ML-DSA-44',
    'ML-DSA-65',
    'ML-DSA-87',
    'ML-KEM-512',
    'ML-KEM-768',
    'ML-KEM-1024',
  ]),
  importKey: new Set([
    'RSASSA-PKCS1-v1_5',
    'RSA-PSS',
    'RSA-OAEP',
    'ECDSA',
    'ECDH',
    'Ed25519',
    'Ed448',
    'X25519',
    'X448',
    'AES-CTR',
    'AES-CBC',
    'AES-GCM',
    'AES-KW',
    'AES-OCB',
    'ChaCha20-Poly1305',
    'HMAC',
    'KMAC128',
    'KMAC256',
    'HKDF',
    'PBKDF2',
    'Argon2d',
    'Argon2i',
    'Argon2id',
    'ML-DSA-44',
    'ML-DSA-65',
    'ML-DSA-87',
    'ML-KEM-512',
    'ML-KEM-768',
    'ML-KEM-1024',
  ]),
  exportKey: new Set([
    'RSASSA-PKCS1-v1_5',
    'RSA-PSS',
    'RSA-OAEP',
    'ECDSA',
    'ECDH',
    'Ed25519',
    'Ed448',
    'X25519',
    'X448',
    'AES-CTR',
    'AES-CBC',
    'AES-GCM',
    'AES-KW',
    'AES-OCB',
    'ChaCha20-Poly1305',
    'HMAC',
    'KMAC128',
    'KMAC256',
    'ML-DSA-44',
    'ML-DSA-65',
    'ML-DSA-87',
    'ML-KEM-512',
    'ML-KEM-768',
    'ML-KEM-1024',
  ]),
  deriveBits: new Set([
    'PBKDF2',
    'HKDF',
    'ECDH',
    'X25519',
    'X448',
    'Argon2d',
    'Argon2i',
    'Argon2id',
  ]),
  wrapKey: new Set([
    'AES-CTR',
    'AES-CBC',
    'AES-GCM',
    'AES-KW',
    'AES-OCB',
    'ChaCha20-Poly1305',
    'RSA-OAEP',
  ]),
  unwrapKey: new Set([
    'AES-CTR',
    'AES-CBC',
    'AES-GCM',
    'AES-KW',
    'AES-OCB',
    'ChaCha20-Poly1305',
    'RSA-OAEP',
  ]),
  encapsulateBits: new Set(['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024']),
  decapsulateBits: new Set(['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024']),
  encapsulateKey: new Set(['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024']),
  decapsulateKey: new Set(['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024']),
};

const ASYMMETRIC_ALGORITHMS = new Set([
  'RSASSA-PKCS1-v1_5',
  'RSA-PSS',
  'RSA-OAEP',
  'ECDSA',
  'ECDH',
  'Ed25519',
  'Ed448',
  'X25519',
  'X448',
  'ML-DSA-44',
  'ML-DSA-65',
  'ML-DSA-87',
  'ML-KEM-512',
  'ML-KEM-768',
  'ML-KEM-1024',
]);

export class Subtle {
  static supports(
    operation: string,
    algorithm: SubtleAlgorithm | AnyAlgorithm,
    _lengthOrAdditionalAlgorithm?: unknown,
  ): boolean {
    let normalizedAlgorithm: SubtleAlgorithm;
    try {
      normalizedAlgorithm = normalizeAlgorithm(
        algorithm,
        (operation === 'getPublicKey' ? 'exportKey' : operation) as Operation,
      );
    } catch {
      return false;
    }

    const name = normalizedAlgorithm.name;

    if (operation === 'getPublicKey') {
      return ASYMMETRIC_ALGORITHMS.has(name);
    }

    if (operation === 'deriveKey') {
      // deriveKey decomposes to deriveBits + importKey of additional algorithm
      if (!SUPPORTED_ALGORITHMS.deriveBits?.has(name)) return false;
      if (_lengthOrAdditionalAlgorithm != null) {
        try {
          const additionalAlg = normalizeAlgorithm(
            _lengthOrAdditionalAlgorithm as SubtleAlgorithm | AnyAlgorithm,
            'importKey',
          );
          return (
            SUPPORTED_ALGORITHMS.importKey?.has(additionalAlg.name) ?? false
          );
        } catch {
          return false;
        }
      }
      return true;
    }

    const supported = SUPPORTED_ALGORITHMS[operation];
    if (!supported) return false;
    return supported.has(name);
  }

  async decrypt(
    algorithm: EncryptDecryptParams,
    key: CryptoKey,
    data: BufferLike,
  ): Promise<ArrayBuffer> {
    const normalizedAlgorithm = normalizeAlgorithm(algorithm, 'decrypt');
    return cipherOrWrap(
      CipherOrWrapMode.kWebCryptoCipherDecrypt,
      normalizedAlgorithm as EncryptDecryptParams,
      key,
      bufferLikeToArrayBuffer(data),
      'decrypt',
    );
  }

  async digest(
    algorithm: SubtleAlgorithm | AnyAlgorithm,
    data: BufferLike,
  ): Promise<ArrayBuffer> {
    const normalizedAlgorithm = normalizeAlgorithm(
      algorithm,
      'digest' as Operation,
    );
    return asyncDigest(normalizedAlgorithm, data);
  }

  async deriveBits(
    algorithm: SubtleAlgorithm,
    baseKey: CryptoKey,
    length: number,
  ): Promise<ArrayBuffer> {
    // WebCrypto §SubtleCrypto.deriveBits step 11: throw InvalidAccessError
    // unless `baseKey.[[usages]]` contains "deriveBits" specifically. The
    // previous `deriveBits || deriveKey` accept-either branch silently
    // promoted deriveKey-only keys into deriveBits use, contradicting the
    // spec usage gate.
    if (!baseKey.keyUsages.includes('deriveBits')) {
      throw lazyDOMException(
        'baseKey does not have deriveBits usage',
        'InvalidAccessError',
      );
    }
    if (baseKey.algorithm.name !== algorithm.name)
      throw new Error('Key algorithm mismatch');
    switch (algorithm.name) {
      case 'PBKDF2':
        return pbkdf2DeriveBits(algorithm, baseKey, length);
      case 'X25519':
      // Fall through
      case 'X448':
        return xDeriveBits(algorithm, baseKey, length);
      case 'ECDH':
        return ecDeriveBits(algorithm, baseKey, length);
      case 'HKDF':
        return hkdfDeriveBits(
          algorithm as unknown as HkdfAlgorithm,
          baseKey,
          length,
        );
      case 'Argon2d':
      case 'Argon2i':
      case 'Argon2id':
        return argon2DeriveBits(algorithm, baseKey, length);
    }
    throw new Error(
      `'subtle.deriveBits()' for ${algorithm.name} is not implemented.`,
    );
  }

  async deriveKey(
    algorithm: SubtleAlgorithm,
    baseKey: CryptoKey,
    derivedKeyAlgorithm: SubtleAlgorithm,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey> {
    // Validate baseKey usage
    if (
      !baseKey.usages.includes('deriveKey') &&
      !baseKey.usages.includes('deriveBits')
    ) {
      throw lazyDOMException(
        'baseKey does not have deriveKey or deriveBits usage',
        'InvalidAccessError',
      );
    }

    // Calculate required key length
    const length = getKeyLength(derivedKeyAlgorithm);

    // Step 1: Derive bits
    let derivedBits: ArrayBuffer;
    if (baseKey.algorithm.name !== algorithm.name)
      throw new Error('Key algorithm mismatch');

    switch (algorithm.name) {
      case 'PBKDF2':
        derivedBits = await pbkdf2DeriveBits(algorithm, baseKey, length);
        break;
      case 'X25519':
      // Fall through
      case 'X448':
        derivedBits = await xDeriveBits(algorithm, baseKey, length);
        break;
      case 'ECDH':
        derivedBits = await ecDeriveBits(algorithm, baseKey, length);
        break;
      case 'HKDF':
        derivedBits = hkdfDeriveBits(
          algorithm as unknown as HkdfAlgorithm,
          baseKey,
          length,
        );
        break;
      case 'Argon2d':
      case 'Argon2i':
      case 'Argon2id':
        derivedBits = argon2DeriveBits(algorithm, baseKey, length);
        break;
      default:
        throw new Error(
          `'subtle.deriveKey()' for ${algorithm.name} is not implemented.`,
        );
    }

    // Step 2: Import as key. Use 'raw-secret' so derived material flows into
    // AEADs / KMAC correctly — they reject plain 'raw' (Node webcrypto.js:381-385).
    return this.importKey(
      'raw-secret',
      derivedBits,
      derivedKeyAlgorithm,
      extractable,
      keyUsages,
    );
  }

  async encrypt(
    algorithm: EncryptDecryptParams,
    key: CryptoKey,
    data: BufferLike,
  ): Promise<ArrayBuffer> {
    const normalizedAlgorithm = normalizeAlgorithm(algorithm, 'encrypt');
    return cipherOrWrap(
      CipherOrWrapMode.kWebCryptoCipherEncrypt,
      normalizedAlgorithm as EncryptDecryptParams,
      key,
      bufferLikeToArrayBuffer(data),
      'encrypt',
    );
  }

  async exportKey(
    format: ImportFormat,
    key: CryptoKey,
  ): Promise<ArrayBuffer | JWK> {
    if (!key.extractable)
      throw lazyDOMException('key is not extractable', 'InvalidAccessError');

    if (format === 'raw-seed') {
      const pqcAlgos = [
        'ML-KEM-512',
        'ML-KEM-768',
        'ML-KEM-1024',
        'ML-DSA-44',
        'ML-DSA-65',
        'ML-DSA-87',
      ];
      if (!pqcAlgos.includes(key.algorithm.name)) {
        throw lazyDOMException(
          'raw-seed export only supported for PQC keys',
          'NotSupportedError',
        );
      }
      if (key.type !== 'private') {
        throw lazyDOMException(
          'raw-seed export requires a private key',
          'InvalidAccessError',
        );
      }
      return bufferLikeToArrayBuffer(key.keyObject.handle.exportKey());
    }

    switch (format) {
      case 'spki':
        return (await exportKeySpki(key)) as ArrayBuffer;
      case 'pkcs8':
        return (await exportKeyPkcs8(key)) as ArrayBuffer;
      case 'jwk':
        return exportKeyJWK(key) as JWK;
      case 'raw':
      case 'raw-secret':
      case 'raw-public':
        return exportKeyRaw(key, format) as ArrayBuffer;
    }
  }

  async wrapKey(
    format: ImportFormat,
    key: CryptoKey,
    wrappingKey: CryptoKey,
    wrapAlgorithm: EncryptDecryptParams,
  ): Promise<ArrayBuffer> {
    // Validate wrappingKey usage
    if (!wrappingKey.usages.includes('wrapKey')) {
      throw lazyDOMException(
        'wrappingKey does not have wrapKey usage',
        'InvalidAccessError',
      );
    }

    // Step 1: Export the key
    const exported = await this.exportKey(format, key);

    // Step 2: Convert to ArrayBuffer if JWK
    let keyData: ArrayBuffer;
    if (format === 'jwk') {
      const jwkString = JSON.stringify(exported);
      const buffer = SBuffer.from(jwkString, 'utf8');

      // For AES-KW, pad to multiple of 8 bytes (accounting for null terminator)
      if (wrapAlgorithm.name === 'AES-KW') {
        const length = buffer.length;
        // Add 1 for null terminator, then pad to multiple of 8
        const paddedLength = Math.ceil((length + 1) / 8) * 8;
        const paddedBuffer = SBuffer.alloc(paddedLength);
        buffer.copy(paddedBuffer);
        // Null terminator for JSON string (remaining bytes are already zeros from alloc)
        paddedBuffer.writeUInt8(0, length);
        keyData = bufferLikeToArrayBuffer(paddedBuffer);
      } else {
        keyData = bufferLikeToArrayBuffer(buffer);
      }
    } else {
      keyData = exported as ArrayBuffer;
    }

    // Step 3: Encrypt the exported key
    return cipherOrWrap(
      CipherOrWrapMode.kWebCryptoCipherEncrypt,
      wrapAlgorithm,
      wrappingKey,
      keyData,
      'wrapKey',
    );
  }

  async unwrapKey(
    format: ImportFormat,
    wrappedKey: BufferLike,
    unwrappingKey: CryptoKey,
    unwrapAlgorithm: EncryptDecryptParams,
    unwrappedKeyAlgorithm: SubtleAlgorithm | AnyAlgorithm,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey> {
    // Validate unwrappingKey usage
    if (!unwrappingKey.usages.includes('unwrapKey')) {
      throw lazyDOMException(
        'unwrappingKey does not have unwrapKey usage',
        'InvalidAccessError',
      );
    }

    // Step 1: Decrypt the wrapped key
    const decrypted = await cipherOrWrap(
      CipherOrWrapMode.kWebCryptoCipherDecrypt,
      unwrapAlgorithm,
      unwrappingKey,
      bufferLikeToArrayBuffer(wrappedKey),
      'unwrapKey',
    );

    // Step 2: Convert to appropriate format
    let keyData: BufferLike | JWK;
    if (format === 'jwk') {
      const buffer = SBuffer.from(decrypted);
      // For AES-KW, the data may be padded - find the null terminator
      let jwkString: string;
      if (unwrapAlgorithm.name === 'AES-KW') {
        // Find the null terminator (if present) to get the original string
        const nullIndex = buffer.indexOf(0);
        if (nullIndex !== -1) {
          jwkString = buffer.toString('utf8', 0, nullIndex);
        } else {
          // No null terminator, try to parse the whole buffer
          jwkString = buffer.toString('utf8').trim();
        }
      } else {
        jwkString = buffer.toString('utf8');
      }
      keyData = JSON.parse(jwkString) as JWK;
    } else {
      keyData = decrypted;
    }

    // Step 3: Import the key
    return this.importKey(
      format,
      keyData,
      unwrappedKeyAlgorithm,
      extractable,
      keyUsages,
    );
  }

  async generateKey(
    algorithm: SubtleAlgorithm,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey | CryptoKeyPair> {
    algorithm = normalizeAlgorithm(algorithm, 'generateKey');
    let result: CryptoKey | CryptoKeyPair;
    switch (algorithm.name) {
      case 'RSASSA-PKCS1-v1_5':
      // Fall through
      case 'RSA-PSS':
      // Fall through
      case 'RSA-OAEP':
        result = await rsa_generateKeyPair(algorithm, extractable, keyUsages);
        break;
      case 'ECDSA':
      // Fall through
      case 'ECDH':
        result = await ec_generateKeyPair(
          algorithm.name,
          algorithm.namedCurve!,
          extractable,
          keyUsages,
        );
        checkCryptoKeyPairUsages(result as CryptoKeyPair);
        break;
      case 'AES-CTR':
      // Fall through
      case 'AES-CBC':
      // Fall through
      case 'AES-GCM':
      // Fall through
      case 'AES-KW':
      // Fall through
      case 'AES-OCB':
        result = await aesGenerateKey(
          algorithm as AesKeyGenParams,
          extractable,
          keyUsages,
        );
        break;
      case 'ChaCha20-Poly1305': {
        const length = (algorithm as AesKeyGenParams).length ?? 256;

        if (length !== 256) {
          throw lazyDOMException(
            'ChaCha20-Poly1305 only supports 256-bit keys',
            'NotSupportedError',
          );
        }

        result = await aesGenerateKey(
          {
            name: 'ChaCha20-Poly1305',
            length: 256,
          } as unknown as AesKeyGenParams,
          extractable,
          keyUsages,
        );
        break;
      }
      case 'HMAC':
        result = await hmacGenerateKey(algorithm, extractable, keyUsages);
        break;
      case 'KMAC128':
      // Fall through
      case 'KMAC256':
        result = await kmacGenerateKey(algorithm, extractable, keyUsages);
        break;
      case 'Ed25519':
      // Fall through
      case 'Ed448':
        result = await ed_generateKeyPairWebCrypto(
          algorithm.name.toLowerCase() as 'ed25519' | 'ed448',
          extractable,
          keyUsages,
        );
        checkCryptoKeyPairUsages(result as CryptoKeyPair);
        break;
      case 'ML-DSA-44':
      // Fall through
      case 'ML-DSA-65':
      // Fall through
      case 'ML-DSA-87':
        result = await mldsa_generateKeyPairWebCrypto(
          algorithm.name as MlDsaVariant,
          extractable,
          keyUsages,
        );
        checkCryptoKeyPairUsages(result as CryptoKeyPair);
        break;
      case 'X25519':
      // Fall through
      case 'X448':
        result = await x_generateKeyPairWebCrypto(
          algorithm.name.toLowerCase() as 'x25519' | 'x448',
          extractable,
          keyUsages,
        );
        checkCryptoKeyPairUsages(result as CryptoKeyPair);
        break;
      case 'ML-KEM-512':
      // Fall through
      case 'ML-KEM-768':
      // Fall through
      case 'ML-KEM-1024':
        result = await mlkem_generateKeyPairWebCrypto(
          algorithm.name as MlKemVariant,
          extractable,
          keyUsages,
        );
        checkCryptoKeyPairUsages(result as CryptoKeyPair);
        break;
      default:
        throw new Error(
          `'subtle.generateKey()' is not implemented for ${algorithm.name}.
            Unrecognized algorithm name`,
        );
    }

    return result;
  }

  async getPublicKey(
    key: CryptoKey,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey> {
    if (key.type === 'secret') {
      throw lazyDOMException('key must be a private key', 'NotSupportedError');
    }
    if (key.type !== 'private') {
      throw lazyDOMException('key must be a private key', 'InvalidAccessError');
    }

    const publicKeyObject = createPublicKey(key.keyObject);
    return publicKeyObject.toCryptoKey(key.algorithm, true, keyUsages);
  }

  async importKey(
    format: ImportFormat,
    data: BufferLike | BinaryLike | JWK,
    algorithm: SubtleAlgorithm | AnyAlgorithm,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey> {
    // Per-algorithm format handling. Some algorithms alias raw-secret/raw-public
    // to 'raw' (RSA, EC, Ed/X, HMAC, HKDF, PBKDF2); others demand the
    // disambiguated form (KMAC, AES-OCB, ChaCha20-Poly1305, Argon2, ML-DSA,
    // ML-KEM). 'raw-seed' is never normalized — PQC import handles it directly.
    const normalizedAlgorithm = normalizeAlgorithm(algorithm, 'importKey');
    let result: CryptoKey;
    switch (normalizedAlgorithm.name) {
      case 'RSASSA-PKCS1-v1_5':
      // Fall through
      case 'RSA-PSS':
      // Fall through
      case 'RSA-OAEP':
        result = rsaImportKey(
          aliasKeyFormat(format),
          data as BufferLike | JWK,
          normalizedAlgorithm,
          extractable,
          keyUsages,
        );
        break;
      case 'ECDSA':
      // Fall through
      case 'ECDH':
        result = ecImportKey(
          aliasKeyFormat(format),
          data,
          normalizedAlgorithm,
          extractable,
          keyUsages,
        );
        break;
      case 'HMAC':
        // No aliasing — Node routes HMAC straight into mac.js, which accepts
        // 'raw' / 'raw-secret' / 'jwk' and rejects everything else
        // (webcrypto.js:774-781, mac.js:136-174).
        result = await hmacImportKey(
          normalizedAlgorithm,
          format,
          data as BufferLike | JWK,
          extractable,
          keyUsages,
        );
        break;
      case 'KMAC128':
      // Fall through
      case 'KMAC256':
        result = await kmacImportKey(
          normalizedAlgorithm,
          format,
          data as BufferLike | JWK,
          extractable,
          keyUsages,
        );
        break;
      case 'AES-CTR':
      // Fall through
      case 'AES-CBC':
      // Fall through
      case 'AES-GCM':
      // Fall through
      case 'AES-KW':
      // Fall through
      case 'AES-OCB':
      // Fall through
      case 'ChaCha20-Poly1305':
        result = await aesImportKey(
          normalizedAlgorithm,
          format,
          data as BufferLike | JWK,
          extractable,
          keyUsages,
        );
        break;
      case 'PBKDF2':
        result = await pbkdf2ImportKey(
          normalizedAlgorithm,
          aliasKeyFormat(format),
          data as BufferLike | BinaryLike,
          extractable,
          keyUsages,
        );
        break;
      case 'Argon2d':
      case 'Argon2i':
      case 'Argon2id':
        result = await argon2ImportKey(
          normalizedAlgorithm,
          format,
          data as BufferLike | BinaryLike,
          extractable,
          keyUsages,
        );
        break;
      case 'HKDF':
        result = await hkdfImportKey(
          aliasKeyFormat(format),
          data as BufferLike | BinaryLike,
          normalizedAlgorithm,
          extractable,
          keyUsages,
        );
        break;
      case 'X25519':
      // Fall through
      case 'X448':
      // Fall through
      case 'Ed25519':
      // Fall through
      case 'Ed448':
        result = edImportKey(
          aliasKeyFormat(format),
          data as BufferLike | JWK,
          normalizedAlgorithm,
          extractable,
          keyUsages,
        );
        break;
      case 'ML-DSA-44':
      // Fall through
      case 'ML-DSA-65':
      // Fall through
      case 'ML-DSA-87':
        result = mldsaImportKey(
          format,
          data as BufferLike | JWK,
          normalizedAlgorithm,
          extractable,
          keyUsages,
        );
        break;
      case 'ML-KEM-512':
      // Fall through
      case 'ML-KEM-768':
      // Fall through
      case 'ML-KEM-1024':
        result = mlkemImportKey(
          format,
          data as BufferLike | JWK,
          normalizedAlgorithm,
          extractable,
          keyUsages,
        );
        break;
      default:
        throw new Error(
          `"subtle.importKey()" is not implemented for ${normalizedAlgorithm.name}`,
        );
    }

    if (
      (result.type === 'secret' || result.type === 'private') &&
      result.usages.length === 0
    ) {
      throw new Error(
        `Usages cannot be empty when importing a ${result.type} key.`,
      );
    }

    return result;
  }

  async sign(
    algorithm: SubtleAlgorithm,
    key: CryptoKey,
    data: BufferLike,
  ): Promise<ArrayBuffer> {
    return signVerify(
      normalizeAlgorithm(algorithm, 'sign'),
      key,
      data,
    ) as ArrayBuffer;
  }

  async verify(
    algorithm: SubtleAlgorithm,
    key: CryptoKey,
    signature: BufferLike,
    data: BufferLike,
  ): Promise<boolean> {
    return signVerify(
      normalizeAlgorithm(algorithm, 'verify'),
      key,
      data,
      signature,
    ) as boolean;
  }

  private _encapsulateCore(
    algorithm: SubtleAlgorithm,
    key: CryptoKey,
  ): EncapsulateResult {
    const normalizedAlgorithm = normalizeAlgorithm(
      algorithm,
      'encapsulateBits' as Operation,
    );

    if (key.algorithm.name !== normalizedAlgorithm.name) {
      throw lazyDOMException('Key algorithm mismatch', 'InvalidAccessError');
    }

    const variant = normalizedAlgorithm.name as MlKemVariant;
    const mlkem = new MlKem(variant);

    const keyData = key.keyObject.handle.exportKey(
      KFormatType.DER,
      KeyEncoding.SPKI,
    );
    mlkem.setPublicKey(
      bufferLikeToArrayBuffer(keyData),
      KFormatType.DER,
      KeyEncoding.SPKI,
    );

    return mlkem.encapsulateSync();
  }

  private _decapsulateCore(
    algorithm: SubtleAlgorithm,
    key: CryptoKey,
    ciphertext: BufferLike,
  ): ArrayBuffer {
    const normalizedAlgorithm = normalizeAlgorithm(
      algorithm,
      'decapsulateBits' as Operation,
    );

    if (key.algorithm.name !== normalizedAlgorithm.name) {
      throw lazyDOMException('Key algorithm mismatch', 'InvalidAccessError');
    }

    const variant = normalizedAlgorithm.name as MlKemVariant;
    const mlkem = new MlKem(variant);

    const keyData = key.keyObject.handle.exportKey(
      KFormatType.DER,
      KeyEncoding.PKCS8,
    );
    mlkem.setPrivateKey(
      bufferLikeToArrayBuffer(keyData),
      KFormatType.DER,
      KeyEncoding.PKCS8,
    );

    return mlkem.decapsulateSync(bufferLikeToArrayBuffer(ciphertext));
  }

  async encapsulateBits(
    algorithm: SubtleAlgorithm,
    key: CryptoKey,
  ): Promise<EncapsulateResult> {
    if (!key.usages.includes('encapsulateBits')) {
      throw lazyDOMException(
        'Key does not have encapsulateBits usage',
        'InvalidAccessError',
      );
    }

    return this._encapsulateCore(algorithm, key);
  }

  async encapsulateKey(
    algorithm: SubtleAlgorithm,
    key: CryptoKey,
    sharedKeyAlgorithm: SubtleAlgorithm | AnyAlgorithm,
    extractable: boolean,
    usages: KeyUsage[],
  ): Promise<{ key: CryptoKey; ciphertext: ArrayBuffer }> {
    if (!key.usages.includes('encapsulateKey')) {
      throw lazyDOMException(
        'Key does not have encapsulateKey usage',
        'InvalidAccessError',
      );
    }

    const { sharedKey, ciphertext } = this._encapsulateCore(algorithm, key);
    // Node imports the encapsulated shared bits as 'raw-secret'
    // (webcrypto.js:1370-1374) so AEADs / KMAC accept the result.
    const importedKey = await this.importKey(
      'raw-secret',
      sharedKey,
      sharedKeyAlgorithm,
      extractable,
      usages,
    );

    return { key: importedKey, ciphertext };
  }

  async decapsulateBits(
    algorithm: SubtleAlgorithm,
    key: CryptoKey,
    ciphertext: BufferLike,
  ): Promise<ArrayBuffer> {
    if (!key.usages.includes('decapsulateBits')) {
      throw lazyDOMException(
        'Key does not have decapsulateBits usage',
        'InvalidAccessError',
      );
    }

    return this._decapsulateCore(algorithm, key, ciphertext);
  }

  async decapsulateKey(
    algorithm: SubtleAlgorithm,
    key: CryptoKey,
    ciphertext: BufferLike,
    sharedKeyAlgorithm: SubtleAlgorithm | AnyAlgorithm,
    extractable: boolean,
    usages: KeyUsage[],
  ): Promise<CryptoKey> {
    if (!key.usages.includes('decapsulateKey')) {
      throw lazyDOMException(
        'Key does not have decapsulateKey usage',
        'InvalidAccessError',
      );
    }

    const sharedKey = this._decapsulateCore(algorithm, key, ciphertext);
    // Node imports the decapsulated shared bits as 'raw-secret'
    // (webcrypto.js:1490-1494).
    return this.importKey(
      'raw-secret',
      sharedKey,
      sharedKeyAlgorithm,
      extractable,
      usages,
    );
  }
}

export const subtle = new Subtle();

function getKeyLength(algorithm: SubtleAlgorithm): number {
  const name = algorithm.name;

  switch (name) {
    case 'AES-CTR':
    case 'AES-CBC':
    case 'AES-GCM':
    case 'AES-KW':
    case 'AES-OCB':
    case 'ChaCha20-Poly1305':
      return (algorithm as AesKeyGenParams).length || 256;

    case 'HMAC': {
      const hmacAlg = algorithm as { length?: number };
      return hmacAlg.length || 256;
    }

    case 'KMAC128':
      return algorithm.length || 128;
    case 'KMAC256':
      return algorithm.length || 256;

    default:
      throw lazyDOMException(
        `Cannot determine key length for ${name}`,
        'NotSupportedError',
      );
  }
}
