import type { AesKeyGenParams, SecretKeyObject, SecretKeyType } from '../keys';

export type GenerateSecretKeyMethod = (
  type: SecretKeyType,
  options: AesKeyGenParams // | HmacKeyGenParams,
) => Promise<SecretKeyObject>;

export type GenerateSecretKeySyncMethod = (
  type: SecretKeyType,
  options: AesKeyGenParams // | HmacKeyGenParams,
) => SecretKeyObject;
