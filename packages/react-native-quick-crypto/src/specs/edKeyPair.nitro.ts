import type { HybridObject } from 'react-native-nitro-modules';

export interface EdKeyPair
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  generateKeyPair(
    publicFormat: number,
    publicType: number,
    privateFormat: number,
    privateType: number,
    cipher?: string,
    passphrase?: ArrayBuffer,
  ): Promise<void>;

  generateKeyPairSync(
    publicFormat: number,
    publicType: number,
    privateFormat: number,
    privateType: number,
    cipher?: string,
    passphrase?: ArrayBuffer,
  ): void;

  getPublicKey(): ArrayBuffer;

  sign(message: ArrayBuffer): Promise<ArrayBuffer>;
  signSync(message: ArrayBuffer): ArrayBuffer;

  verify(signature: ArrayBuffer, message: ArrayBuffer): Promise<boolean>;
  verifySync(signature: ArrayBuffer, message: ArrayBuffer): boolean;

  setCurve(curve: string): void;
}
