import type { HybridObject } from 'react-native-nitro-modules';

export interface DiffieHellman
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  init(prime: ArrayBuffer, generator: ArrayBuffer): void;
  initWithSize(primeLength: number, generator: number): void;
  generateKeys(): ArrayBuffer;
  computeSecret(otherPublicKey: ArrayBuffer): ArrayBuffer;
  getPrime(): ArrayBuffer;
  getGenerator(): ArrayBuffer;
  getPublicKey(): ArrayBuffer;
  getPrivateKey(): ArrayBuffer;
  setPublicKey(publicKey: ArrayBuffer): void;
  setPrivateKey(privateKey: ArrayBuffer): void;
  getVerifyError(): number;
}
