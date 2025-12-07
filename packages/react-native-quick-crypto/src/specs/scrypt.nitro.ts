import type { HybridObject } from 'react-native-nitro-modules';

export interface Scrypt extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  deriveKey(
    password: ArrayBuffer,
    salt: ArrayBuffer,
    N: number,
    r: number,
    p: number,
    maxmem: number,
    keylen: number,
  ): Promise<ArrayBuffer>;

  deriveKeySync(
    password: ArrayBuffer,
    salt: ArrayBuffer,
    N: number,
    r: number,
    p: number,
    maxmem: number,
    keylen: number,
  ): ArrayBuffer;
}
