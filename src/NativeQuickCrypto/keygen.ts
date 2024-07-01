import type { KeyObjectHandle } from './webcrypto';

export type GenerateSecretKeyMethod = (
  length: number
) => Promise<KeyObjectHandle>;

export type GenerateSecretKeySyncMethod = (length: number) => KeyObjectHandle;
