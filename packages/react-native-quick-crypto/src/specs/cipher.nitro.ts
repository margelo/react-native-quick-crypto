import type { HybridObject } from 'react-native-nitro-modules';

type CipherArgs = {
  isCipher: boolean;
  cipherType: string;
  cipherKey: ArrayBuffer;
  iv: ArrayBuffer;
  authTagLen?: number;
};

export interface Cipher extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  update(data: ArrayBuffer): ArrayBuffer;
  final(): ArrayBuffer;
  setArgs(args: CipherArgs): void;
  setAAD(data: ArrayBuffer, plaintextLength?: number): boolean;
  setAutoPadding(autoPad: boolean): boolean;
  setAuthTag(tag: ArrayBuffer): boolean;
  getAuthTag(): ArrayBuffer;
  getSupportedCiphers(): string[];
}

export interface CipherFactory
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  createCipher(args: CipherArgs): Cipher;
}
