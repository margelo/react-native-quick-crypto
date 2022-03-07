import { NativeFastCrypto } from './NativeFastCrypto/NativeFastCrypto';
import * as pbkdf2 from './pbkdf2';
import * as random from './random';

export const FastCrypto = {
  createHmac: NativeFastCrypto.createHmac,
  createHash: NativeFastCrypto.createHash,
  ...pbkdf2,
  ...random,
};
