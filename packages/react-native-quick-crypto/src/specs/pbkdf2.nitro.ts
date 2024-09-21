import { type HybridObject } from 'react-native-nitro-modules';

export interface Pbkdf2 extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  pbkdf2(
    password: ArrayBuffer,
    salt: ArrayBuffer,
    iterations: number,
    keylen: number,
    digest: string,
  ): Promise<ArrayBuffer>;
  pbkdf2Sync(
    password: ArrayBuffer,
    salt: ArrayBuffer,
    iterations: number,
    keylen: number,
    digest: string,
  ): ArrayBuffer;
}
