import type { HybridObject } from 'react-native-nitro-modules';

export interface ECDH extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  init(curveName: string): void;
  generateKeys(): ArrayBuffer;
  computeSecret(otherPublicKey: ArrayBuffer): ArrayBuffer;
  getPrivateKey(): ArrayBuffer;
  setPrivateKey(privateKey: ArrayBuffer): void;
  getPublicKey(): ArrayBuffer;
  setPublicKey(publicKey: ArrayBuffer): void;
  convertKey(key: ArrayBuffer, curve: string, format: number): ArrayBuffer;
}
