import type { HybridObject } from 'react-native-nitro-modules';

//  Nitro-compatible interfaces defined locally
interface KeyObject {
  extractable: boolean;
}

export interface EcKeyPair
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  // generateKeyPair functions
  generateKeyPair(): Promise<void>;
  generateKeyPairSync(): void;

  // importKey
  importKey(
    format: string,
    keyData: ArrayBuffer,
    algorithm: string,
    extractable: boolean,
    keyUsages: string[],
  ): KeyObject;

  // exportKey
  exportKey(key: KeyObject, format: string): ArrayBuffer;

  getPublicKey(): ArrayBuffer;
  getPrivateKey(): ArrayBuffer;

  setCurve(curve: string): void;

  // ECDSA sign/verify operations
  sign(data: ArrayBuffer, hashAlgorithm: string): ArrayBuffer;
  verify(
    data: ArrayBuffer,
    signature: ArrayBuffer,
    hashAlgorithm: string,
  ): boolean;

  getSupportedCurves(): string[];
}
