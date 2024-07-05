import type { CipherOrWrapMode, DigestAlgorithm } from '../keys';
import type { RSAKeyVariant } from '../rsa';
import type { KeyObjectHandle } from './webcrypto';

export type RSACipher = (
  mode: CipherOrWrapMode,
  handle: KeyObjectHandle,
  data: ArrayBuffer,
  variant: RSAKeyVariant,
  hash: DigestAlgorithm,
  label?: ArrayBuffer
) => Promise<ArrayBuffer>;
