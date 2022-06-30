import { NativeQuickCrypto } from './NativeQuickCrypto/NativeQuickCrypto';
import type { InternalSign } from './NativeQuickCrypto/sig';

const createInternalSign = NativeQuickCrypto.createSign;

class Sign {
  private internal: InternalSign;
  constructor(algorithm: string, options: any) {
    this.internal = createInternalSign();
  }
}

export function createSign(algorithm: string, options: any) {
  return new Sign(algorithm, options);
}
