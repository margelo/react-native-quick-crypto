import { type HybridObject } from 'react-native-nitro-modules';

export interface Prime extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  generatePrime(
    size: number,
    safe: boolean,
    add?: ArrayBuffer,
    rem?: ArrayBuffer,
  ): Promise<ArrayBuffer>;
  generatePrimeSync(
    size: number,
    safe: boolean,
    add?: ArrayBuffer,
    rem?: ArrayBuffer,
  ): ArrayBuffer;
  checkPrime(candidate: ArrayBuffer, checks: number): Promise<boolean>;
  checkPrimeSync(candidate: ArrayBuffer, checks: number): boolean;
}
