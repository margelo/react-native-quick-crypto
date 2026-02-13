import type { HybridObject } from 'react-native-nitro-modules';

type CipherArgs = {
  isCipher: boolean;
  cipherType: string;
  cipherKey: ArrayBuffer;
  iv: ArrayBuffer;
  authTagLen?: number;
};

interface CipherInfo {
  name: string;
  nid: number;
  mode: string;
  keyLength: number;
  blockSize?: number;
  ivLength?: number;
}

export interface Cipher extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  update(data: ArrayBuffer): ArrayBuffer;
  final(): ArrayBuffer;
  setArgs(args: CipherArgs): void;
  setAAD(data: ArrayBuffer, plaintextLength?: number): boolean;
  setAutoPadding(autoPad: boolean): boolean;
  setAuthTag(tag: ArrayBuffer): boolean;
  getAuthTag(): ArrayBuffer;
  getSupportedCiphers(): string[];
  getCipherInfo(
    name: string,
    keyLength?: number,
    ivLength?: number,
  ): CipherInfo | undefined;
}

export interface CipherFactory
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  createCipher(args: CipherArgs): Cipher;
}
