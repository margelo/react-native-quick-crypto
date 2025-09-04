import type { HybridObject } from 'react-native-nitro-modules';

// Nitro-compatible interfaces defined locally
interface KeyObject {
  extractable: boolean;
}

export interface RsaKeyPair
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  // generateKeyPair functions
  generateKeyPair(): Promise<void>;
  generateKeyPairSync(): void;

  // RSA-specific setters
  setModulusLength(modulusLength: number): void;
  setPublicExponent(publicExponent: ArrayBuffer): void;
  setHashAlgorithm(hashAlgorithm: string): void;

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
}
