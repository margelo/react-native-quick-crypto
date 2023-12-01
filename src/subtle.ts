import {
  type ImportFormat,
  type SubtleAlgorithm,
  type KeyUsage,
  CryptoKey,
  KWebCryptoKeyFormat,
} from './keys';
import { ecImportKey, ecExportKey } from './ec';
import type { BufferLike } from './Utils';

class Subtle {
  async importKey(
    format: ImportFormat,
    data: BufferLike,
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
      // case 'PBKDF2':
      //   result = await importGenericSecretKey(
      //     algorithm,
      //     format,
      //     keyData,
      //     extractable,
      //     keyUsages
      //   );
      //   break;
      default:
        throw new Error(`Unrecognized algorithm name ${algorithm.name}`);
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

  async exportKey(format: ImportFormat, key: CryptoKey) {
    if (!key.extractable) throw new Error('key is not extractable');

    switch (format) {
      case 'spki':
        return this.exportKeySpki(key);
      // case 'jwk':
      //   return exportKeyJWK(key);
      // case 'raw':
      //   return exportKeyRaw(key);
    }
    throw new Error('Export format is unsupported');
  }

  private async exportKeySpki(key: CryptoKey) {
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
  }
}

export const subtle = new Subtle();
