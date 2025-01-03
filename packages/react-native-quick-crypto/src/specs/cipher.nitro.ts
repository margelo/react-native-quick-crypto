import type { HybridObject } from 'react-native-nitro-modules';

export interface Cipher
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
    update(data: ArrayBuffer): ArrayBuffer;
    final: () => ArrayBuffer;
    copy: () => void;
    setAAD: (data: ArrayBuffer, plaintextLength?: number) => boolean;
    setAutoPadding: (autoPad: boolean) => boolean;
    setAuthTag: (tag: ArrayBuffer) => boolean;
    getAuthTag: () => ArrayBuffer;
}
