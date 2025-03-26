import { Buffer } from 'safe-buffer';
import { createSecretKey, CryptoKey, type ImportFormat, type JWK, type KeyUsage, type SubtleAlgorithm } from './keys';
import { 
  type BufferLike,
  lazyDOMException,
  hasAnyNotIn 
} from './Utils';

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
      'Invalid key usages for HMAC',
      'SyntaxError'
    );
  }

  let keyMaterial: Buffer;

  switch (format) {
    case 'raw': {
      // For raw format, keyData should be BufferLike
      if (typeof keyData === 'string') {
        keyMaterial = Buffer.from(keyData, 'utf8');
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
        throw lazyDOMException(
          'Invalid JWK format for HMAC key',
          'DataError'
        );
      }

      // Convert base64url to buffer
      keyMaterial = Buffer.from(jwk.k, 'base64');
      
      // If algorithm.length is specified, validate key length
      if (algorithm.length && keyMaterial.length * 8 !== algorithm.length) {
        throw lazyDOMException(
          'Invalid key length',
          'DataError'
        );
      }

      break;
    }

    default:
      throw lazyDOMException(
        `Unable to import HMAC key with format ${format}`,
        'NotSupportedError'
      );
  }

  // Create the key object
  const keyObject = createSecretKey(keyMaterial);

  // Return new CryptoKey
  return new CryptoKey(
    keyObject,
    algorithm,
    keyUsages,
    extractable
  );
}
