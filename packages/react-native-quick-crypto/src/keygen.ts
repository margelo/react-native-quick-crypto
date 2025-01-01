import { NativeQuickCrypto } from './NativeQuickCrypto/NativeQuickCrypto';
import { lazyDOMException, validateFunction } from './Utils';
import { kAesKeyLengths } from './aes';
import {
  SecretKeyObject,
  type SecretKeyType,
  type AesKeyGenParams,
} from './keys';

export type KeyGenCallback = (
  err: Error | undefined,
  key?: SecretKeyObject,
) => void;

export const generateKeyPromise = (
  type: SecretKeyType,
  options: AesKeyGenParams, // | HmacKeyGenParams
): Promise<[Error | undefined, SecretKeyObject | undefined]> => {
  return new Promise((resolve, reject) => {
    generateKey(type, options, (err, key) => {
      if (err) {
        reject([err, undefined]);
      }
      resolve([undefined, key]);
    });
  });
};

export const generateKey = (
  type: SecretKeyType,
  options: AesKeyGenParams, // | HmacKeyGenParams,
  callback: KeyGenCallback,
): void => {
  validateLength(type, options.length);
  if (!validateFunction(callback)) {
    throw lazyDOMException('Callback is not a function', 'SyntaxError');
  }
  NativeQuickCrypto.webcrypto
    .generateSecretKey(options.length)
    .then((handle) => {
      callback(undefined, new SecretKeyObject(handle));
    })
    .catch((err) => {
      callback(err, undefined);
    });
};

export const generateKeySync = (
  type: SecretKeyType,
  options: AesKeyGenParams, // | HmacKeyGenParams,
): SecretKeyObject => {
  validateLength(type, options.length);
  const handle = NativeQuickCrypto.webcrypto.generateSecretKeySync(
    options.length,
  );
  return new SecretKeyObject(handle);
};

const validateLength = (type: SecretKeyType, length: number) => {
  switch (type) {
    case 'aes':
      if (!kAesKeyLengths.includes(length)) {
        throw lazyDOMException(
          'AES key length must be 128, 192, or 256 bits',
          'OperationError',
        );
      }
      break;
    case 'hmac':
      if (length < 8 || length > 2 ** 31 - 1) {
        throw lazyDOMException(
          'HMAC key length must be between 8 and 2^31 - 1',
          'OperationError',
        );
      }
      break;
    default:
      throw new Error(`Unsupported key type '${type}' for generateKey()`);
  }
};
