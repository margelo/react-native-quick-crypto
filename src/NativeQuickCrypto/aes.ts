import type { AESKeyVariant } from '../aes';
import type { CipherOrWrapMode } from '../keys';
import type { KeyObjectHandle } from './webcrypto';

export type AESCipher = (
  mode: CipherOrWrapMode,
  handle: KeyObjectHandle,
  data: ArrayBuffer,
  variant: AESKeyVariant,
  param1?: any,
  param2?: any,
  param3?: any
) => Promise<ArrayBuffer>;
