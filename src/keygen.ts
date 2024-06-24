import { NativeQuickCrypto } from './NativeQuickCrypto/NativeQuickCrypto';
import { validateFunction } from './Utils';
import {
  SecretKeyObject,
  type AesKeyGenParams,
  type SecretKeyType,
} from './keys';

export type KeyGenCallback = (err: Error | null, key?: SecretKeyObject) => void;

export const generateKey = async (
  type: SecretKeyType,
  options: AesKeyGenParams, // | HmacKeyGenParams,
  callback: KeyGenCallback
): Promise<SecretKeyObject> => {
  validateFunction(callback);
  return await NativeQuickCrypto.webcrypto.generateSecretKey(type, options);
};

export const generateKeySync = (
  type: SecretKeyType,
  options: AesKeyGenParams // | HmacKeyGenParams,
): SecretKeyObject => {
  return NativeQuickCrypto.webcrypto.generateSecretKeySync(type, options);
};
