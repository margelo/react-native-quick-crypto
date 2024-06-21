import type { AESKeyVariant } from '../aes';
import type { CipherOrWrapMode } from '../keys';
import type { KeyObjectHandle } from './webcrypto';

export type AESCipher = (
  mode: CipherOrWrapMode,
  handle: KeyObjectHandle,
  data: ArrayBuffer,
  variant: AESKeyVariant,
  iv_or_counter?: ArrayBuffer,
  length?: number,
  authTag?: ArrayBuffer,
  additionalData?: ArrayBuffer
) => Promise<ArrayBuffer>;
