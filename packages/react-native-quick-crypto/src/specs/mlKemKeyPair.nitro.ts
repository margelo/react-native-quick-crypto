import type { HybridObject } from 'react-native-nitro-modules';

export interface MlKemKeyPair
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  setVariant(variant: string): void;

  generateKeyPair(
    publicFormat: number,
    publicType: number,
    privateFormat: number,
    privateType: number,
  ): Promise<void>;

  generateKeyPairSync(
    publicFormat: number,
    publicType: number,
    privateFormat: number,
    privateType: number,
  ): void;

  getPublicKey(): ArrayBuffer;
  getPrivateKey(): ArrayBuffer;

  setPublicKey(keyData: ArrayBuffer, format: number, type: number): void;
  setPrivateKey(keyData: ArrayBuffer, format: number, type: number): void;

  encapsulate(): Promise<ArrayBuffer>;
  encapsulateSync(): ArrayBuffer;

  decapsulate(ciphertext: ArrayBuffer): Promise<ArrayBuffer>;
  decapsulateSync(ciphertext: ArrayBuffer): ArrayBuffer;
}
