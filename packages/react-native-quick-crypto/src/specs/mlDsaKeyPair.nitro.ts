import type { HybridObject } from 'react-native-nitro-modules';

export interface MlDsaKeyPair
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
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

  sign(message: ArrayBuffer): Promise<ArrayBuffer>;
  signSync(message: ArrayBuffer): ArrayBuffer;

  verify(signature: ArrayBuffer, message: ArrayBuffer): Promise<boolean>;
  verifySync(signature: ArrayBuffer, message: ArrayBuffer): boolean;

  setVariant(variant: string): void;
}
