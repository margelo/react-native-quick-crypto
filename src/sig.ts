import { NativeQuickCrypto } from './NativeQuickCrypto/NativeQuickCrypto';
import type { InternalSign } from './NativeQuickCrypto/sig';
import {
  BinaryLike,
  binaryLikeToArrayBuffer,
  getDefaultEncoding,
} from './Utils';

const createInternalSign = NativeQuickCrypto.createSign;

class Sign {
  private internal: InternalSign;
  constructor(algorithm: string, options: any) {
    this.internal = createInternalSign();
    console.warn('init response', this.internal.init(algorithm));
  }

  _write(chunk: BinaryLike, encoding: string, callback: () => void) {
    this.update(chunk, encoding);
    callback();
  }

  update(data: BinaryLike, encoding?: string) {
    encoding = encoding ?? getDefaultEncoding();
    data = binaryLikeToArrayBuffer(data);
    this.internal.update(data);
    return this;
  }
}

export function createSign(algorithm: string, options: any) {
  return new Sign(algorithm, options);
}
