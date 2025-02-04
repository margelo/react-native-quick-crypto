import type { HybridObject } from 'react-native-nitro-modules';

export interface Hash extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  createHash(algorithm: string, outputLength?: number): void;
  update(data: ArrayBuffer): void;
  digest(encoding?: string): ArrayBuffer;
  copy(outputLength?: number): Hash;
  getSupportedHashAlgorithms(): string[];
}
