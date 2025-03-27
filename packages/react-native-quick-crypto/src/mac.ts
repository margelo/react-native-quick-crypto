import { Buffer } from '@craftzdog/react-native-buffer';
import {
  createSecretKey,
  CryptoKey,
  type ImportFormat,
  type JWK,
  type KeyUsage,
  type SubtleAlgorithm,
} from './keys';
import { type BufferLike, lazyDOMException, hasAnyNotIn } from './Utils';

export async function hmacImportKey(
  algorithm: SubtleAlgorithm,
  format: ImportFormat,
  keyData: BufferLike | JWK,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKey> {
  // Validate key usages
  if (hasAnyNotIn(keyUsages, ['sign', 'verify'])) {
    throw lazyDOMException(
      'Unsupported key usage for an HMAC key',
      'SyntaxError',
    );
  }

  if (!keyData) {
    throw lazyDOMException('Invalid keyData', 'DataError');
  }

  let keyMaterial: Buffer;

  switch (format) {
    case 'raw': {
      // For raw format, keyData should be BufferLike
      if (typeof keyData === 'string') {
        keyMaterial = Buffer.from(keyData, 'base64');
      } else if (Buffer.isBuffer(keyData)) {
        keyMaterial = keyData;
      } else {
        keyMaterial = Buffer.from(keyData as ArrayBuffer);
      }
      break;
    }

    case 'jwk': {
      const jwk = keyData as JWK;

      // Validate required JWK properties
      if (typeof jwk !== 'object' || jwk.kty !== 'oct' || !jwk.k) {
        throw lazyDOMException('Invalid JWK format for HMAC key', 'DataError');
      }

      if (algorithm.length === 0) {
        throw lazyDOMException('Zero-length key is not supported', 'DataError');
      }

      // The Web Crypto spec allows for key lengths that are not multiples of 8. We don't.
      if (algorithm.length && algorithm.length % 8) {
        throw lazyDOMException(
          'Unsupported algorithm.length',
          'NotSupportedError',
        );
      }

      // Convert base64 to buffer
      keyMaterial = Buffer.from(jwk.k, 'base64');

      // If algorithm.length is specified, validate key length
      if (algorithm.length && keyMaterial.length * 8 !== algorithm.length) {
        throw lazyDOMException('Invalid key length', 'DataError');
      }

      break;
    }

    default:
      throw lazyDOMException(
        `Unable to import HMAC key with format ${format}`,
        'NotSupportedError',
      );
  }

  // Create the key object
  const keyObject = createSecretKey(keyMaterial);

  // Return new CryptoKey
  return new CryptoKey(keyObject, algorithm, keyUsages, extractable);
}
