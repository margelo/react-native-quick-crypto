import { NativeQuickCrypto } from './NativeQuickCrypto/NativeQuickCrypto';
import { lazyDOMException, validateFunction } from './Utils';
import { kAesKeyLengths } from './aes';
import {
  SecretKeyObject,
  type SecretKeyType,
  type AesKeyGenParams,
} from './keys';

export type KeyGenCallback = (err: Error | null, key?: SecretKeyObject) => void;

export const generateKey = async (
  type: SecretKeyType,
  options: AesKeyGenParams, // | HmacKeyGenParams,
  callback: KeyGenCallback
): Promise<SecretKeyObject> => {
  validateLength(type, options.length);
  validateFunction(callback);
  const handle = await NativeQuickCrypto.webcrypto.generateSecretKey(
    options.length
  );
  return new SecretKeyObject(handle);
};

export const generateKeySync = (
  type: SecretKeyType,
  options: AesKeyGenParams // | HmacKeyGenParams,
): SecretKeyObject => {
  validateLength(type, options.length);
  const handle = NativeQuickCrypto.webcrypto.generateSecretKeySync(
    options.length
  );
  return new SecretKeyObject(handle);
};

const validateLength = (type: SecretKeyType, length: number) => {
  switch (type) {
    case 'aes':
      if (!kAesKeyLengths.includes(length)) {
        throw lazyDOMException(
          'AES key length must be 128, 192, or 256 bits',
          'OperationError'
        );
      }
      break;
    case 'hmac':
      if (length < 8 || length > 2 ** 31 - 1) {
        throw lazyDOMException(
          'HMAC key length must be between 8 and 2^31 - 1',
          'OperationError'
        );
      }
      break;
    default:
      throw new Error(`Unsupported key type '${type}' for generateKey()`);
  }
};
