import {
  type ImportFormat,
  type BufferLike,
  type SubtleAlgorithm,
  type KeyUsage,
  CryptoKey,
} from './keys';
import { ecImportKey } from './ec';

class Subtle {
  async importKey(
    format: ImportFormat,
    data: BufferLike,
    algorithm: SubtleAlgorithm,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<CryptoKey> {
    let result;
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
        throw new Error('Unrecognized algorithm name');
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
}

export const subtle = new Subtle();
