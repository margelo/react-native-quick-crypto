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
  getPrivateKey(): ArrayBuffer;

  sign(message: ArrayBuffer, key?: ArrayBuffer): Promise<ArrayBuffer>;
  signSync(message: ArrayBuffer, key?: ArrayBuffer): ArrayBuffer;

  verify(
    message: ArrayBuffer,
    signature: ArrayBuffer,
    key?: ArrayBuffer,
  ): Promise<boolean>;
  verifySync(
    message: ArrayBuffer,
    signature: ArrayBuffer,
    key?: ArrayBuffer,
  ): boolean;

  setCurve(curve: string): void;
}
