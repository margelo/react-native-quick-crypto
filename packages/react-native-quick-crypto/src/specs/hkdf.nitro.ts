import type { HybridObject } from 'react-native-nitro-modules';

// mode: 'full' (extract+expand), 'extract' (PRK only), or 'expand' (from PRK).
export interface Hkdf extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  deriveKeySync(
    algorithm: string,
    key: ArrayBuffer,
    salt: ArrayBuffer,
    info: ArrayBuffer,
    length: number,
    mode: string,
  ): ArrayBuffer;

  deriveKey(
    algorithm: string,
    key: ArrayBuffer,
    salt: ArrayBuffer,
    info: ArrayBuffer,
    length: number,
    mode: string,
  ): Promise<ArrayBuffer>;
}
