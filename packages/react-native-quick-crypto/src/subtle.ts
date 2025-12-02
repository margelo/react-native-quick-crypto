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
  RsaOaepParams,
} from './utils';
import { KFormatType, KeyEncoding } from './utils';
import {
  CryptoKey,
  KeyObject,
  PublicKeyObject,
  PrivateKeyObject,
  SecretKeyObject,
} from './keys';
import type { CryptoKeyPair } from './utils/types';
import { bufferLikeToArrayBuffer } from './utils/conversion';
import { lazyDOMException } from './utils/errors';
import { normalizeHashName, HashContext } from './utils/hashnames';
import { validateMaxBufferLength } from './utils/validation';
import { asyncDigest } from './hash';
import { createSecretKey } from './keys';
import { NitroModules } from 'react-native-nitro-modules';
import type { KeyObjectHandle } from './specs/keyObjectHandle.nitro';
import type { RsaCipher } from './specs/rsaCipher.nitro';
import type { CipherFactory } from './specs/cipher.nitro';
import { pbkdf2DeriveBits } from './pbkdf2';
import { ecImportKey, ecdsaSignVerify, ec_generateKeyPair } from './ec';
import { rsa_generateKeyPair } from './rsa';
import { getRandomValues } from './random';
import { createHmac } from './hmac';
import { createSign, createVerify } from './keys/signVerify';
import { ed_generateKeyPairWebCrypto, Ed } from './ed';
// import { pbkdf2DeriveBits } from './pbkdf2';
// import { aesCipher, aesGenerateKey, aesImportKey, getAlgorithmName } from './aes';
// import { rsaCipher, rsaExportKey, rsaImportKey, rsaKeyGenerate } from './rsa';
// import { normalizeAlgorithm, type Operation } from './algorithms';
// import { hmacImportKey } from './mac';

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

function normalizeAlgorithm(
  algorithm: SubtleAlgorithm | AnyAlgorithm,
  _operation: Operation,
): SubtleAlgorithm {
  if (typeof algorithm === 'string') {
    return { name: algorithm };
  }
  return algorithm as SubtleAlgorithm;
}

function getAlgorithmName(name: string, length: number): string {
  return `${name}${length}`;
}

// Placeholder implementations for missing functions
function ecExportKey(key: CryptoKey, format: KWebCryptoKeyFormat): ArrayBuffer {
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

async function aesGcmCipher(
  mode: CipherOrWrapMode,
  key: CryptoKey,
  data: ArrayBuffer,
  algorithm: AesGcmParams,
): Promise<ArrayBuffer> {
  const { tagLength = 128 } = algorithm;

  // Validate tag length
  const validTagLengths = [32, 64, 96, 104, 112, 120, 128];
  if (!validTagLengths.includes(tagLength)) {
    throw lazyDOMException(
      `${tagLength} is not a valid AES-GCM tag length`,
      'OperationError',
    );
  }

  const tagByteLength = tagLength / 8;

  // Get cipher type based on key length
  const keyLength = (key.algorithm as { length: number }).length;
  const cipherType = `aes-${keyLength}-gcm`;

  // Create cipher
  const factory =
    NitroModules.createHybridObject<CipherFactory>('CipherFactory');
  const cipher = factory.createCipher({
    isCipher: mode === CipherOrWrapMode.kWebCryptoCipherEncrypt,
    cipherType,
    cipherKey: bufferLikeToArrayBuffer(key.keyObject.export()),
    iv: bufferLikeToArrayBuffer(algorithm.iv),
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
  if (algorithm.additionalData) {
    cipher.setAAD(bufferLikeToArrayBuffer(algorithm.additionalData));
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

  // Construct algorithm object
  const keyAlgorithm: SubtleAlgorithm = {
    name: 'HMAC',
    hash: hashName,
    length,
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

  // Validate usages
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

  if (hasAnyNotIn(keyUsages, checkSet)) {
    throw new Error(`Unsupported key usage for ${name}`);
  }

  let keyObject: KeyObject;

  if (format === 'jwk') {
    const jwk = data as JWK;

    // Validate JWK
    if (jwk.kty !== 'RSA') {
      throw new Error('Invalid JWK format for RSA key');
    }

    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    const keyType = handle.initJwk(jwk, undefined);

    if (keyType === undefined) {
      throw new Error('Failed to import RSA JWK');
    }

    // Create the appropriate KeyObject based on type
    if (keyType === 1) {
      keyObject = new PublicKeyObject(handle);
    } else if (keyType === 2) {
      keyObject = new PrivateKeyObject(handle);
    } else {
      throw new Error('Unexpected key type from RSA JWK import');
    }
  } else if (format === 'spki') {
    const keyData = bufferLikeToArrayBuffer(data as BufferLike);
    keyObject = KeyObject.createKeyObject(
      'public',
      keyData,
      KFormatType.DER,
      KeyEncoding.SPKI,
    );
  } else if (format === 'pkcs8') {
    const keyData = bufferLikeToArrayBuffer(data as BufferLike);
    keyObject = KeyObject.createKeyObject(
      'private',
      keyData,
      KFormatType.DER,
      KeyEncoding.PKCS8,
    );
  } else {
    throw new Error(`Unsupported format for RSA import: ${format}`);
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

  const algorithmWithDetails = {
    ...algorithm,
    modulusLength: keyDetails?.modulusLength,
    publicExponent: publicExponentBytes,
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
  // Validate usages
  if (hasAnyNotIn(keyUsages, ['sign', 'verify'])) {
    throw new Error('Unsupported key usage for an HMAC key');
  }

  let keyObject: KeyObject;

  if (format === 'jwk') {
    const jwk = data as JWK;

    // Validate JWK
    if (!jwk || typeof jwk !== 'object') {
      throw new Error('Invalid keyData');
    }

    if (jwk.kty !== 'oct') {
      throw new Error('Invalid JWK format for HMAC key');
    }

    // Validate key length if specified
    if (algorithm.length !== undefined) {
      if (!jwk.k) {
        throw new Error('JWK missing key data');
      }
      // Decode to check length
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
    const keyType = handle.initJwk(jwk, undefined);

    if (keyType === undefined || keyType !== 0) {
      throw new Error('Failed to import HMAC JWK');
    }

    keyObject = new SecretKeyObject(handle);
  } else if (format === 'raw') {
    keyObject = createSecretKey(data as BinaryLike);
  } else {
    throw new Error(`Unable to import HMAC key with format ${format}`);
  }

  return new CryptoKey(
    keyObject,
    { ...algorithm, name: 'HMAC' },
    keyUsages,
    extractable,
  );
}

async function aesImportKey(
  algorithm: SubtleAlgorithm,
  format: ImportFormat,
  data: BufferLike | JWK,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKey> {
  const { name, length } = algorithm;

  // Validate usages
  const validUsages: KeyUsage[] = [
    'encrypt',
    'decrypt',
    'wrapKey',
    'unwrapKey',
  ];
  if (hasAnyNotIn(keyUsages, validUsages)) {
    throw new Error(`Unsupported key usage for ${name}`);
  }

  let keyObject: KeyObject;
  let actualLength: number;

  if (format === 'jwk') {
    const jwk = data as JWK;

    // Validate JWK
    if (jwk.kty !== 'oct') {
      throw new Error('Invalid JWK format for AES key');
    }

    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    const keyType = handle.initJwk(jwk, undefined);

    if (keyType === undefined || keyType !== 0) {
      throw new Error('Failed to import AES JWK');
    }

    keyObject = new SecretKeyObject(handle);

    // Get actual key length from imported key
    const exported = keyObject.export();
    actualLength = exported.byteLength * 8;
  } else if (format === 'raw') {
    const keyData = bufferLikeToArrayBuffer(data as BufferLike);
    actualLength = keyData.byteLength * 8;

    // Validate key length
    if (![128, 192, 256].includes(actualLength)) {
      throw new Error('Invalid AES key length');
    }

    keyObject = createSecretKey(keyData);
  } else {
    throw new Error(`Unsupported format for AES import: ${format}`);
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
  data: BufferLike,
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): CryptoKey {
  const { name } = algorithm;

  // Validate usages
  if (hasAnyNotIn(keyUsages, ['sign', 'verify'])) {
    throw lazyDOMException(
      `Unsupported key usage for ${name} key`,
      'SyntaxError',
    );
  }

  let keyObject: KeyObject;

  if (format === 'spki') {
    // Import public key
    const keyData = bufferLikeToArrayBuffer(data);
    keyObject = KeyObject.createKeyObject(
      'public',
      keyData,
      KFormatType.DER,
      KeyEncoding.SPKI,
    );
  } else if (format === 'pkcs8') {
    // Import private key
    const keyData = bufferLikeToArrayBuffer(data);
    keyObject = KeyObject.createKeyObject(
      'private',
      keyData,
      KFormatType.DER,
      KeyEncoding.PKCS8,
    );
  } else if (format === 'raw') {
    // Raw format - public key only for Ed keys
    const keyData = bufferLikeToArrayBuffer(data);
    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    // For raw Ed keys, we need to create them differently
    // Raw public keys are just the key bytes
    handle.init(1, keyData); // 1 = public key type
    keyObject = new PublicKeyObject(handle);
  } else {
    throw lazyDOMException(
      `Unsupported format for ${name} import: ${format}`,
      'NotSupportedError',
    );
  }

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
      if (key.type === 'public') {
        // Export Ed key in SPKI DER format
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
      if (key.type === 'private') {
        // Export Ed key in PKCS8 DER format
        return bufferLikeToArrayBuffer(
          key.keyObject.handle.exportKey(KFormatType.DER, KeyEncoding.PKCS8),
        );
      }
      break;
  }

  throw new Error(
    `Unable to export a pkcs8 ${key.algorithm.name} ${key.type} key`,
  );
};

const exportKeyRaw = (key: CryptoKey): ArrayBuffer | unknown => {
  switch (key.algorithm.name) {
    case 'ECDSA':
    // Fall through
    case 'ECDH':
      if (key.type === 'public') {
        return ecExportKey(key, KWebCryptoKeyFormat.kWebCryptoKeyFormatRaw);
      }
      break;
    case 'AES-CTR':
    // Fall through
    case 'AES-CBC':
    // Fall through
    case 'AES-GCM':
    // Fall through
    case 'AES-KW':
    // Fall through
    case 'HMAC': {
      const exported = key.keyObject.export();
      // Convert Buffer to ArrayBuffer
      return exported.buffer.slice(
        exported.byteOffset,
        exported.byteOffset + exported.byteLength,
      );
    }
  }

  throw lazyDOMException(
    `Unable to export a raw ${key.algorithm.name} ${key.type} key`,
    'InvalidAccessError',
  );
};

const exportKeyJWK = (key: CryptoKey): ArrayBuffer | unknown => {
  const jwk = key.keyObject.handle.exportJwk(
    {
      key_ops: key.usages,
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
    case 'ECDSA':
    // Fall through
    case 'ECDH':
      jwk.crv ||= key.algorithm.namedCurve;
      return jwk;
    case 'AES-CTR':
    // Fall through
    case 'AES-CBC':
    // Fall through
    case 'AES-GCM':
    // Fall through
    case 'AES-KW':
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

const importGenericSecretKey = async (
  { name, length }: SubtleAlgorithm,
  format: ImportFormat,
  keyData: BufferLike | BinaryLike,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKey> => {
  if (extractable) {
    throw new Error(`${name} keys are not extractable`);
  }
  if (hasAnyNotIn(keyUsages, ['deriveKey', 'deriveBits'])) {
    throw new Error(`Unsupported key usage for a ${name} key`);
  }

  switch (format) {
    case 'raw': {
      if (hasAnyNotIn(keyUsages, ['deriveKey', 'deriveBits'])) {
        throw new Error(`Unsupported key usage for a ${name} key`);
      }

      const checkLength =
        typeof keyData === 'string' || SBuffer.isBuffer(keyData)
          ? keyData.length * 8
          : keyData.byteLength * 8;

      if (length !== undefined && length !== checkLength) {
        throw new Error('Invalid key length');
      }

      const keyObject = createSecretKey(keyData as BinaryLike);
      return new CryptoKey(keyObject, { name }, keyUsages, false);
    }
  }

  throw new Error(`Unable to import ${name} key with format ${format}`);
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

  // Verify operation - compare computed HMAC with provided signature
  const sigBytes = new Uint8Array(bufferLikeToArrayBuffer(signature));
  const computedBytes = new Uint8Array(
    computed.buffer,
    computed.byteOffset,
    computed.byteLength,
  );

  if (computedBytes.length !== sigBytes.length) {
    return false;
  }

  // Constant-time comparison to prevent timing attacks
  let result = 0;
  for (let i = 0; i < computedBytes.length; i++) {
    result |= computedBytes[i]! ^ sigBytes[i]!;
  }
  return result === 0;
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
      return aesCipher(mode, key, data, algorithm);
  }
};

export class Subtle {
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
    if (!baseKey.keyUsages.includes('deriveBits')) {
      throw new Error('baseKey does not have deriveBits usage');
    }
    if (baseKey.algorithm.name !== algorithm.name)
      throw new Error('Key algorithm mismatch');
    switch (algorithm.name) {
      case 'PBKDF2':
        return pbkdf2DeriveBits(algorithm, baseKey, length);
    }
    throw new Error(
      `'subtle.deriveBits()' for ${algorithm.name} is not implemented.`,
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
    if (!key.extractable) throw new Error('key is not extractable');

    switch (format) {
      case 'spki':
        return (await exportKeySpki(key)) as ArrayBuffer;
      case 'pkcs8':
        return (await exportKeyPkcs8(key)) as ArrayBuffer;
      case 'jwk':
        return exportKeyJWK(key) as JWK;
      case 'raw':
        return exportKeyRaw(key) as ArrayBuffer;
    }
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
        result = await aesGenerateKey(
          algorithm as AesKeyGenParams,
          extractable,
          keyUsages,
        );
        break;
      case 'HMAC':
        result = await hmacGenerateKey(algorithm, extractable, keyUsages);
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
      default:
        throw new Error(
          `'subtle.generateKey()' is not implemented for ${algorithm.name}.
            Unrecognized algorithm name`,
        );
    }

    return result;
  }

  async importKey(
    format: ImportFormat,
    data: BufferLike | BinaryLike | JWK,
    algorithm: SubtleAlgorithm | AnyAlgorithm,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey> {
    const normalizedAlgorithm = normalizeAlgorithm(algorithm, 'importKey');
    let result: CryptoKey;
    switch (normalizedAlgorithm.name) {
      case 'RSASSA-PKCS1-v1_5':
      // Fall through
      case 'RSA-PSS':
      // Fall through
      case 'RSA-OAEP':
        result = rsaImportKey(
          format,
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
          format,
          data,
          normalizedAlgorithm,
          extractable,
          keyUsages,
        );
        break;
      case 'HMAC':
        result = await hmacImportKey(
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
        result = await aesImportKey(
          normalizedAlgorithm,
          format,
          data as BufferLike | JWK,
          extractable,
          keyUsages,
        );
        break;
      case 'PBKDF2':
        result = await importGenericSecretKey(
          normalizedAlgorithm,
          format,
          data as BufferLike | BinaryLike,
          extractable,
          keyUsages,
        );
        break;
      case 'Ed25519':
      // Fall through
      case 'Ed448':
        result = edImportKey(
          format,
          data as BufferLike,
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
    return signVerify(algorithm, key, data) as ArrayBuffer;
  }

  async verify(
    algorithm: SubtleAlgorithm,
    key: CryptoKey,
    signature: BufferLike,
    data: BufferLike,
  ): Promise<ArrayBuffer> {
    return signVerify(algorithm, key, data, signature) as ArrayBuffer;
  }
}

export const subtle = new Subtle();
