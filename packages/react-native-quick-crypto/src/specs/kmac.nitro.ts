import type { HybridObject } from 'react-native-nitro-modules';

export interface Kmac extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  createKmac(
    algorithm: string,
    key: ArrayBuffer,
    outputLength: number,
    customization?: ArrayBuffer,
  ): void;
  update(data: ArrayBuffer): void;
  digest(): ArrayBuffer;
}
