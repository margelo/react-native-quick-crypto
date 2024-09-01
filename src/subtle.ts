import { Buffer as SBuffer } from 'safe-buffer';
import {
  type ImportFormat,
  type SubtleAlgorithm,
  type KeyUsage,
  CryptoKey,
  KWebCryptoKeyFormat,
  createSecretKey,
  type AnyAlgorithm,
  type JWK,
  type CryptoKeyPair,
  CipherOrWrapMode,
  type EncryptDecryptParams,
  type AesKeyGenParams,
} from './keys';
import {
  hasAnyNotIn,
  type BufferLike,
  type BinaryLike,
  normalizeAlgorithm,
  lazyDOMException,
  normalizeHashName,
  HashContext,
  type Operation,
  validateMaxBufferLength,
  bufferLikeToArrayBuffer,
} from './Utils';
import { ecImportKey, ecExportKey, ecGenerateKey, ecdsaSignVerify } from './ec';
import { pbkdf2DeriveBits } from './pbkdf2';
import { asyncDigest } from './Hash';
import {
  aesCipher,
  aesGenerateKey,
  aesImportKey,
  getAlgorithmName,
} from './aes';
import { rsaCipher, rsaExportKey, rsaImportKey, rsaKeyGenerate } from './rsa';

const exportKeySpki = async (key: CryptoKey): Promise<ArrayBuffer | unknown> => {
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
    // case 'Ed25519':
    // // Fall through
    // case 'Ed448':
    // // Fall through
    // case 'X25519':
    // // Fall through
    // case 'X448':
    //   if (key.type === 'public') {
    //     return cfrgExportKey(key, KWebCryptoKeyFormat.kWebCryptoKeyFormatSPKI);
    //   }
    //   break;
  }

  throw new Error(
    `Unable to export a spki ${key.algorithm.name} ${key.type} key`
  );
};

const exportKeyPkcs8 = async (key: CryptoKey): Promise<ArrayBuffer | unknown> => {
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
    // case 'Ed25519':
    // // Fall through
    // case 'Ed448':
    // // Fall through
    // case 'X25519':
    // // Fall through
    // case 'X448':
    //   if (key.type === 'private') {
    //     return cfrgExportKey(key, KWebCryptoKeyFormat.kWebCryptoKeyFormatPKCS8);
    //   }
    //   break;
  }

  throw new Error(
    `Unable to export a pkcs8 ${key.algorithm.name} ${key.type} key`
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
    // case 'Ed25519':
    //   // Fall through
    // case 'Ed448':
    //   // Fall through
    // case 'X25519':
    //   // Fall through
    // case 'X448':
    //   if (key.type === 'public') {
    //     return require('internal/crypto/cfrg')
    //       .cfrgExportKey(key, kWebCryptoKeyFormatRaw);
    //   }
    //   break;
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
    'InvalidAccessError'
  );
};

const exportKeyJWK = (key: CryptoKey): ArrayBuffer | unknown => {
  const jwk = key.keyObject.handle.exportJwk(
    {
      key_ops: key.usages,
      ext: key.extractable,
    },
    true
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
    case 'ECDSA':
    // Fall through
    case 'ECDH':
      jwk.crv ||= key.algorithm.namedCurve;
      return jwk;
    // case 'X25519':
    //   // Fall through
    // case 'X448':
    //   jwk.crv ||= key.algorithm.name;
    //   return jwk;
    // case 'Ed25519':
    //   // Fall through
    // case 'Ed448':
    //   jwk.crv ||= key.algorithm.name;
    //   return jwk;
    case 'AES-CTR':
    // Fall through
    case 'AES-CBC':
    // Fall through
    case 'AES-GCM':
    // Fall through
    case 'AES-KW':
      jwk.alg = getAlgorithmName(key.algorithm.name, key.algorithm.length);
      return jwk;
    // case 'HMAC':
    //   jwk.alg = normalizeHashName(
    //     key.algorithm.hash.name,
    //     normalizeHashName.kContextJwkHmac);
    //   return jwk;
    default:
    // Fall through
  }

  throw lazyDOMException(
    `JWK export not yet supported: ${key.algorithm.name}`,
    'NotSupportedError'
  );
};

const importGenericSecretKey = async (
  { name, length }: SubtleAlgorithm,
  format: ImportFormat,
  keyData: BufferLike | BinaryLike,
  extractable: boolean,
  keyUsages: KeyUsage[]
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
        (typeof keyData === 'string') || SBuffer.isBuffer(keyData)
          ? keyData.length * 8
          : keyData.byteLength * 8;

      // The Web Crypto spec allows for key lengths that are not multiples of
      // 8. We don't. Our check here is stricter than that defined by the spec
      // in that we require that algorithm.length match keyData.length * 8 if
      // algorithm.length is specified.
      if (length !== undefined && length !== checkLength) {
        throw new Error('Invalid key length');
      }

      const keyObject = createSecretKey(keyData as BinaryLike);
      return new CryptoKey(keyObject, { name }, keyUsages, false);
    }
  }

  throw new Error(`Unable to import ${name} key with format ${format}`);
};

// const checkCryptoKeyUsages = (key: CryptoKey) => {
//   if (
//     (key.type === 'secret' || key.type === 'private') &&
//     key.usages.length === 0
//   ) {
//     throw lazyDOMException(
//       'Usages cannot be empty when creating a key.',
//       'SyntaxError'
//     );
//   }
// };

const checkCryptoKeyPairUsages = (pair: CryptoKeyPair) => {
  if (
    !(pair.privateKey instanceof Buffer) &&
    pair.privateKey &&
    Object.prototype.hasOwnProperty.call(pair.privateKey, 'keyUsages')
  ) {
    const priv = pair.privateKey as CryptoKey;
    if (priv.usages.length > 0) {
      return;
    }
  }
  console.log(pair.privateKey);
  throw lazyDOMException(
    'Usages cannot be empty when creating a key.',
    'SyntaxError'
  );
};

const signVerify = (
  algorithm: SubtleAlgorithm,
  key: CryptoKey,
  data: BufferLike,
  signature?: BufferLike
): ArrayBuffer | boolean => {
  const usage: Operation = signature === undefined ? 'sign' : 'verify';
  algorithm = normalizeAlgorithm(algorithm, usage);

  if (!key.usages.includes(usage) || algorithm.name !== key.algorithm.name) {
    throw lazyDOMException(
      `Unable to use this key to ${usage}`,
      'InvalidAccessError'
    );
  }

  switch (algorithm.name) {
    // case 'RSA-PSS':
    // // Fall through
    // case 'RSASSA-PKCS1-v1_5':
    //   return require('internal/crypto/rsa').rsaSignVerify(
    //     key,
    //     data,
    //     algorithm,
    //     signature
    //   );
    case 'ECDSA':
      return ecdsaSignVerify(key, data, algorithm, signature);
    // case 'Ed25519':
    // // Fall through
    // case 'Ed448':
    //   return require('internal/crypto/cfrg').eddsaSignVerify(
    //     key,
    //     data,
    //     algorithm,
    //     signature
    //   );
    // case 'HMAC':
    //   return require('internal/crypto/mac').hmacSignVerify(
    //     key,
    //     data,
    //     algorithm,
    //     signature
    //   );
  }
  throw lazyDOMException(
    `Unrecognized algorithm name '${algorithm}' for '${usage}'`,
    'NotSupportedError'
  );
};

const cipherOrWrap = async (
  mode: CipherOrWrapMode,
  algorithm: EncryptDecryptParams, // | WrapUnwrapParams,
  key: CryptoKey,
  data: ArrayBuffer,
  op: Operation
): Promise<ArrayBuffer> => {
  // We use a Node.js style error here instead of a DOMException because
  // the WebCrypto spec is not specific what kind of error is to be thrown
  // in this case. Both Firefox and Chrome throw simple TypeErrors here.
  // The key algorithm and cipher algorithm must match, and the
  // key must have the proper usage.
  if (
    key.algorithm.name !== algorithm.name ||
    !key.usages.includes(op as KeyUsage)
  ) {
    throw lazyDOMException(
      'The requested operation is not valid for the provided key',
      'InvalidAccessError'
    );
  }

  // While WebCrypto allows for larger input buffer sizes, we limit
  // those to sizes that can fit within uint32_t because of limitations
  // in the OpenSSL API.
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
    // case 'AES-KW':
    //   if (op === 'wrapKey' || op === 'unwrapKey') {
    //     return aesCipher(mode, key, data, algorithm);
    //   }
  }
  // @ts-expect-error unreachable code
  throw lazyDOMException(
    `Unrecognized algorithm name '${algorithm}' for '${op}'`,
    'NotSupportedError'
  );
};

export class Subtle {
  async decrypt(
    algorithm: EncryptDecryptParams,
    key: CryptoKey,
    data: BufferLike
  ): Promise<ArrayBuffer> {
    const normalizedAlgorithm = normalizeAlgorithm(algorithm, 'decrypt');
    return cipherOrWrap(
      CipherOrWrapMode.kWebCryptoCipherDecrypt,
      normalizedAlgorithm as EncryptDecryptParams,
      key,
      bufferLikeToArrayBuffer(data),
      'decrypt'
    );
  }

  async digest(
    algorithm: SubtleAlgorithm | AnyAlgorithm,
    data: BufferLike
  ): Promise<ArrayBuffer> {
    const normalizedAlgorithm = normalizeAlgorithm(algorithm, 'digest');
    return asyncDigest(normalizedAlgorithm, data);
  }

  async deriveBits(
    algorithm: SubtleAlgorithm,
    baseKey: CryptoKey,
    length: number
  ): Promise<ArrayBuffer> {
    if (!baseKey.keyUsages.includes('deriveBits')) {
      throw new Error('baseKey does not have deriveBits usage');
    }
    if (baseKey.algorithm.name !== algorithm.name)
      throw new Error('Key algorithm mismatch');
    switch (algorithm.name) {
      // case 'X25519':
      //   // Fall through
      // case 'X448':
      //   // Fall through
      // case 'ECDH':
      //   return require('internal/crypto/diffiehellman')
      //     .ecdhDeriveBits(algorithm, baseKey, length);
      // case 'HKDF':
      //   return require('internal/crypto/hkdf')
      //     .hkdfDeriveBits(algorithm, baseKey, length);
      case 'PBKDF2':
        return pbkdf2DeriveBits(algorithm, baseKey, length);
    }
    throw new Error(
      `'subtle.deriveBits()' for ${algorithm.name} is not implemented.`
    );
  }

  async encrypt(
    algorithm: EncryptDecryptParams,
    key: CryptoKey,
    data: BufferLike
  ): Promise<ArrayBuffer> {
    const normalizedAlgorithm = normalizeAlgorithm(algorithm, 'encrypt');
    return cipherOrWrap(
      CipherOrWrapMode.kWebCryptoCipherEncrypt,
      normalizedAlgorithm as EncryptDecryptParams,
      key,
      bufferLikeToArrayBuffer(data),
      'encrypt'
    );
  }

  async exportKey(
    format: ImportFormat,
    key: CryptoKey
  ): Promise<ArrayBuffer | JWK> {
    if (!key.extractable) throw new Error('key is not extractable');

    switch (format) {
      case 'spki':
        return await exportKeySpki(key) as ArrayBuffer;
      case 'pkcs8':
        return await exportKeyPkcs8(key) as ArrayBuffer;
      case 'jwk':
        return exportKeyJWK(key) as JWK;
      case 'raw':
        return exportKeyRaw(key) as ArrayBuffer;
    }
  }

  async generateKey(
    algorithm: SubtleAlgorithm,
    extractable: boolean,
    keyUsages: KeyUsage[]
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
      // case 'Ed25519':
      // // Fall through
      // case 'Ed448':
      // // Fall through
      // case 'X25519':
      // // Fall through
      // case 'X448':
      //   resultType = 'CryptoKeyPair';
      //   result = await cfrgGenerateKey(algorithm, extractable, keyUsages);
      //   break;
      case 'ECDSA':
      // Fall through
      case 'ECDH':
        result = await ecGenerateKey(algorithm, extractable, keyUsages);
        checkCryptoKeyPairUsages(result);
        break;
      // case 'HMAC':
      //   result = await hmacGenerateKey(algorithm, extractable, keyUsages);
      //   break;
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
          keyUsages
        );
        break;
      default:
        throw new Error(
          `'subtle.generateKey()' is not implemented for ${algorithm.name}.
            Unrecognized algorithm name`
        );
    }

    return result;
  }

  async importKey(
    format: ImportFormat,
    data: BufferLike | BinaryLike | JWK,
    algorithm: SubtleAlgorithm | AnyAlgorithm,
    extractable: boolean,
    keyUsages: KeyUsage[]
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
          keyUsages
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
          keyUsages
        );
        break;
      // case 'Ed25519':
      // // Fall through
      // case 'Ed448':
      // // Fall through
      // case 'X25519':
      // // Fall through
      // case 'X448':
      //   result = await require('internal/crypto/cfrg').cfrgImportKey(
      //     format,
      //     keyData,
      //     algorithm,
      //     extractable,
      //     keyUsages
      //   );
      //   break;
      // case 'HMAC':
      //   result = await require('internal/crypto/mac').hmacImportKey(
      //     format,
      //     keyData,
      //     algorithm,
      //     extractable,
      //     keyUsages
      //   );
      //   break;
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
          keyUsages
        );
        break;
      // case 'HKDF':
      // // Fall through
      case 'PBKDF2':
        result = await importGenericSecretKey(
          normalizedAlgorithm,
          format,
          data as BufferLike | BinaryLike,
          extractable,
          keyUsages
        );
        break;
      default:
        throw new Error(
          `"subtle.importKey()" is not implemented for ${normalizedAlgorithm.name}`
        );
    }

    if (
      (result.type === 'secret' || result.type === 'private') &&
      result.usages.length === 0
    ) {
      throw new Error(
        `Usages cannot be empty when importing a ${result.type} key.`
      );
    }

    return result;
  }

  async sign(
    algorithm: SubtleAlgorithm,
    key: CryptoKey,
    data: BufferLike
  ): Promise<ArrayBuffer> {
    return signVerify(algorithm, key, data) as ArrayBuffer;
  }

  async verify(
    algorithm: SubtleAlgorithm,
    key: CryptoKey,
    signature: BufferLike,
    data: BufferLike
  ): Promise<ArrayBuffer> {
    return signVerify(algorithm, key, data, signature) as ArrayBuffer;
  }
}

export const subtle = new Subtle();
