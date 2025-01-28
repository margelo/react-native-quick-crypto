import type { HybridObject } from 'react-native-nitro-modules';

export interface Hash extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  createHash(algorithm: string): ArrayBuffer;
  update(): void;
  digest(): void;
}
