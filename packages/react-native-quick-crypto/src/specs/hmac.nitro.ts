import type { HybridObject } from 'react-native-nitro-modules';

export interface Hmac extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  createHmac(algorithm: string, key: ArrayBuffer): void;
  update(data: ArrayBuffer): void;
  digest(): ArrayBuffer;
}
