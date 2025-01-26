import type { HybridObject } from 'react-native-nitro-modules';
import type { TransformOptions } from 'readable-stream';

export interface Hash extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  copy(options: TransformOptions[]): ArrayBuffer;
}
