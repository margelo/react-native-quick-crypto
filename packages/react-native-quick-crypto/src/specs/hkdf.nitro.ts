import type { HybridObject } from 'react-native-nitro-modules';

// RFC 5869 stage: 'full' (extract+expand), 'extract' (PRK only), or
// 'expand' (from an existing PRK).
export type HkdfMode = 'full' | 'extract' | 'expand';

export interface Hkdf extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  deriveKeySync(
    algorithm: string,
    key: ArrayBuffer,
    salt: ArrayBuffer,
    info: ArrayBuffer,
    length: number,
    mode: HkdfMode,
  ): ArrayBuffer;

  deriveKey(
    algorithm: string,
    key: ArrayBuffer,
    salt: ArrayBuffer,
    info: ArrayBuffer,
    length: number,
    mode: HkdfMode,
  ): Promise<ArrayBuffer>;
}
