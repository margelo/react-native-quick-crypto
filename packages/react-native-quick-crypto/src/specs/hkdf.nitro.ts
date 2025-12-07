import type { HybridObject } from 'react-native-nitro-modules';

export interface Hkdf extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  deriveKeySync(
    algorithm: string,
    key: ArrayBuffer,
    salt: ArrayBuffer,
    info: ArrayBuffer,
    length: number,
  ): ArrayBuffer;

  deriveKey(
    algorithm: string,
    key: ArrayBuffer,
    salt: ArrayBuffer,
    info: ArrayBuffer,
    length: number,
  ): Promise<ArrayBuffer>;
}
