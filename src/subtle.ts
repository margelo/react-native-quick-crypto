import {
  type ImportFormat,
  type SubtleAlgorithm,
  type KeyUsage,
  CryptoKey,
  KWebCryptoKeyFormat,
  createSecretKey,
  type AnyAlgorithm,
} from './keys';
import { ecImportKey, ecExportKey } from './ec';
import {
  hasAnyNotIn,
  type BufferLike,
  type BinaryLike,
  normalizeAlgorithm,
} from './Utils';
import { pbkdf2DeriveBits } from './pbkdf2';
import { asyncDigest } from './Hash';

const exportKeySpki = async (key: CryptoKey): Promise<ArrayBuffer | any> => {
  switch (key.algorithm.name) {
    // case 'RSASSA-PKCS1-v1_5':
    // // Fall through
    // case 'RSA-PSS':
    // // Fall through
    // case 'RSA-OAEP':
    //   if (key.type === 'public') {
    //     return require('internal/crypto/rsa').rsaExportKey(
    //       key,
    //       kWebCryptoKeyFormatSPKI
    //     );
    //   }
    //   break;
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
    //     return require('internal/crypto/cfrg').cfrgExportKey(
    //       key,
    //       kWebCryptoKeyFormatSPKI
    //     );
    //   }
    //   break;
  }

  throw new Error(
    `Unable to export a raw ${key.algorithm.name} ${key.type} key`
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
        typeof keyData === 'string'
          ? keyData.length * 8
          : keyData.byteLength * 8;

      // The Web Crypto spec allows for key lengths that are not multiples of
      // 8. We don't. Our check here is stricter than that defined by the spec
      // in that we require that algorithm.length match keyData.length * 8 if
      // algorithm.length is specified.
      if (length !== undefined && length !== checkLength) {
        throw new Error('Invalid key length');
      }

      const keyObject = createSecretKey(keyData);
      return new CryptoKey(keyObject, { name }, keyUsages, false);
    }
  }

  throw new Error(`Unable to import ${name} key with format ${format}`);
};

class Subtle {
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

  async importKey(
    format: ImportFormat,
    data: BufferLike | BinaryLike,
    algorithm: SubtleAlgorithm,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<CryptoKey> {
    let result: CryptoKey;
    switch (algorithm.name) {
      // case 'RSASSA-PKCS1-v1_5':
      // // Fall through
      // case 'RSA-PSS':
      // // Fall through
      // case 'RSA-OAEP':
      //   result = await require('internal/crypto/rsa').rsaImportKey(
      //     format,
      //     keyData,
      //     algorithm,
      //     extractable,
      //     keyUsages
      //   );
      //   break;
      case 'ECDSA':
      // Fall through
      case 'ECDH':
        result = await ecImportKey(
          format,
          data,
          algorithm,
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
      // case 'AES-CTR':
      // // Fall through
      // case 'AES-CBC':
      // // Fall through
      // case 'AES-GCM':
      // // Fall through
      // case 'AES-KW':
      //   result = await require('internal/crypto/aes').aesImportKey(
      //     algorithm,
      //     format,
      //     keyData,
      //     extractable,
      //     keyUsages
      //   );
      //   break;
      // case 'HKDF':
      // // Fall through
      case 'PBKDF2':
        result = await importGenericSecretKey(
          algorithm,
          format,
          data,
          extractable,
          keyUsages
        );
        break;
      default:
        throw new Error(
          `'subtle.importKey()' is not implemented for ${algorithm.name}`
        );
    }

    // if (
    //   (result.type === 'secret' || result.type === 'private') &&
    //   result.usages.length === 0
    // ) {
    //   throw new Error(
    //     `Usages cannot be empty when importing a ${result.type} key.`
    //   );
    // }

    return result;
  }

  async exportKey(
    format: ImportFormat,
    key: CryptoKey
  ): Promise<ArrayBuffer | any> {
    if (!key.extractable) throw new Error('key is not extractable');

    switch (format) {
      case 'spki':
        return await exportKeySpki(key);
      // case 'jwk':
      //   return exportKeyJWK(key);
      // case 'raw':
      //   return exportKeyRaw(key);
    }
    throw new Error(`'subtle.exportKey()' is not implemented for ${format}`);
  }
}

export const subtle = new Subtle();
