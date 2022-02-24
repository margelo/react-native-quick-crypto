import { NativeFastCrypto } from './NativeFastCrypto';

async function runAsync(): Promise<number> {
  return NativeFastCrypto.runAsync();
}

export const FastCrypto = {
  runAsync,
};
