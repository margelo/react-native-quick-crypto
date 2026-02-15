import type { HybridObject } from 'react-native-nitro-modules';

export interface DhKeyPair
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  generateKeyPair(): Promise<void>;
  generateKeyPairSync(): void;

  setPrimeLength(primeLength: number): void;
  setPrime(prime: ArrayBuffer): void;
  setGenerator(generator: number): void;

  getPublicKey(): ArrayBuffer;
  getPrivateKey(): ArrayBuffer;
}
