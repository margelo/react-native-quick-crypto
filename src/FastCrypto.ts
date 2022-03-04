import { NativeFastCrypto } from './NativeFastCrypto/NativeFastCrypto';
import * as pbkdf2 from './pbkdf2';
import * as random from './random';

async function runAsync(): Promise<number> {
  return NativeFastCrypto.runAsync();
}

export const FastCrypto = {
  runAsync,
  createHmac: NativeFastCrypto.createHmac,
  createHash: NativeFastCrypto.createHash,
  ...pbkdf2,
  ...random,
};
