import type { HybridObject } from 'react-native-nitro-modules';

export interface Hash extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  update(): void;
  digest(): void;
}
