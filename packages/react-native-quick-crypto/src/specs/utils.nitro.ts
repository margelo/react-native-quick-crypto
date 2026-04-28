import { type HybridObject } from 'react-native-nitro-modules';

export interface Utils extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  timingSafeEqual(a: ArrayBuffer, b: ArrayBuffer): boolean;
}
