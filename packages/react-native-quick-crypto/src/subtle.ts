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
} from './utils';
import { CryptoKey, KeyObject } from './keys';
import type { CryptoKeyPair } from './utils/types';
import { bufferLikeToArrayBuffer } from './utils/conversion';
import { lazyDOMException } from './utils/errors';
import { normalizeHashName, HashContext } from './utils/hashnames';
import { validateMaxBufferLength } from './utils/validation';
import { asyncDigest } from './hash';
import { createSecretKey } from './keys';
import { pbkdf2DeriveBits } from './pbkdf2';

// Placeholder imports - these modules need to be implemented or adapted
// import { ecImportKey, ecExportKey, ecGenerateKey, ecdsaSignVerify } from './ec';
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
function ecExportKey(
  _key: CryptoKey,
  _format: KWebCryptoKeyFormat,
): ArrayBuffer {
  throw new Error('ecExportKey not implemented');
}

function rsaExportKey(
  _key: CryptoKey,
  _format: KWebCryptoKeyFormat,
): ArrayBuffer {
  throw new Error('rsaExportKey not implemented');
}

function ecdsaSignVerify(
  _key: CryptoKey,
  _data: BufferLike,
  _algorithm: SubtleAlgorithm,
  _signature?: BufferLike,
): ArrayBuffer | boolean {
  throw new Error('ecdsaSignVerify not implemented');
}

function rsaCipher(
  _mode: CipherOrWrapMode,
  _key: CryptoKey,
  _data: ArrayBuffer,
  _algorithm: EncryptDecryptParams,
): Promise<ArrayBuffer> {
  throw new Error('rsaCipher not implemented');
}

function aesCipher(
  _mode: CipherOrWrapMode,
  _key: CryptoKey,
  _data: ArrayBuffer,
  _algorithm: EncryptDecryptParams,
): Promise<ArrayBuffer> {
  throw new Error('aesCipher not implemented');
}

async function rsaKeyGenerate(
  _algorithm: SubtleAlgorithm,
  _extractable: boolean,
  _keyUsages: KeyUsage[],
): Promise<CryptoKeyPair> {
  throw new Error('rsaKeyGenerate not implemented');
}

async function ecGenerateKey(
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKeyPair> {
  // Temporary implementation - create mock CryptoKey objects
  const mockKeyObject = {} as KeyObject;
  const publicKey = new CryptoKey(
    mockKeyObject,
    algorithm,
    keyUsages,
    extractable,
  );
  const privateKey = new CryptoKey(
    mockKeyObject,
    algorithm,
    keyUsages,
    extractable,
  );

  return {
    publicKey,
    privateKey,
  };
}

async function aesGenerateKey(
  _algorithm: AesKeyGenParams,
  _extractable: boolean,
  _keyUsages: KeyUsage[],
): Promise<CryptoKey> {
  throw new Error('aesGenerateKey not implemented');
}

function rsaImportKey(
  _format: ImportFormat,
  _data: BufferLike | JWK,
  _algorithm: SubtleAlgorithm,
  _extractable: boolean,
  _keyUsages: KeyUsage[],
): CryptoKey {
  throw new Error('rsaImportKey not implemented');
}

function ecImportKey(
  _format: ImportFormat,
  _data: BufferLike | BinaryLike | JWK,
  _algorithm: SubtleAlgorithm,
  _extractable: boolean,
  _keyUsages: KeyUsage[],
): CryptoKey {
  throw new Error('ecImportKey not implemented');
}

async function hmacImportKey(
  _algorithm: SubtleAlgorithm,
  _format: ImportFormat,
  _data: BufferLike | JWK,
  _extractable: boolean,
  _keyUsages: KeyUsage[],
): Promise<CryptoKey> {
  throw new Error('hmacImportKey not implemented');
}

async function aesImportKey(
  _algorithm: SubtleAlgorithm,
  _format: ImportFormat,
  _data: BufferLike | JWK,
  _extractable: boolean,
  _keyUsages: KeyUsage[],
): Promise<CryptoKey> {
  throw new Error('aesImportKey not implemented');
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
    case 'HMAC':
      return key.keyObject.export();
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
  }
  throw lazyDOMException(
    `Unrecognized algorithm name '${algorithm}' for '${usage}'`,
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
        result = await rsaKeyGenerate(algorithm, extractable, keyUsages);
        break;
      case 'ECDSA':
      // Fall through
      case 'ECDH':
        result = await ecGenerateKey(algorithm, extractable, keyUsages);
        checkCryptoKeyPairUsages(result);
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
