import type { HybridObject } from 'react-native-nitro-modules';

export interface DsaKeyPair
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  generateKeyPair(): Promise<void>;
  generateKeyPairSync(): void;

  setModulusLength(modulusLength: number): void;
  setDivisorLength(divisorLength: number): void;

  getPublicKey(): ArrayBuffer;
  getPrivateKey(): ArrayBuffer;
}
