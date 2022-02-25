import { NativeFastCrypto } from './NativeFastCrypto/NativeFastCrypto';

async function runAsync(): Promise<number> {
  return NativeFastCrypto.runAsync();
}

const nativePbkdf2 = NativeFastCrypto.pbkdf2;
async function pbkdf2(...args) {
  return nativePbkdf2.pbkdf2(...args);
}

function pbkdf2Sync(...args) {
  return nativePbkdf2.pbkdf2Sync(...args);
}

export const FastCrypto = {
  runAsync,
  createHmac: NativeFastCrypto.createHmac,
  pbkdf2, // TODO add wrapper as crypto.pbkdf2 doesn't provide promise like api
  pbkdf2Sync,
};
