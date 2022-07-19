/* eslint-disable no-dupe-class-members */
import { NativeQuickCrypto } from './NativeQuickCrypto/NativeQuickCrypto';
import type { InternalHmac } from './NativeQuickCrypto/hmac';
import {
  Encoding,
  toArrayBuffer,
  BinaryLike,
  binaryLikeToArrayBuffer,
} from './Utils';
import Stream from 'stream-browserify';
import { Buffer } from '@craftzdog/react-native-buffer';

const createInternalHmac = NativeQuickCrypto.createHmac;

export function createHmac(
  algorithm: string,
  key: BinaryLike,
  options?: Stream.TransformOptions
) {
  return new Hmac(algorithm, key, options);
}

class Hmac extends Stream.Transform {
  private internalHmac: InternalHmac;
  private isFinalized: boolean = false;

  constructor(
    algorithm: string,
    key: BinaryLike,
    _options?: Stream.TransformOptions
  ) {
    super();
    let keyAsString = binaryLikeToArrayBuffer(key);

    if (keyAsString === undefined) {
      throw 'Wrong key type';
    }

    this.internalHmac = createInternalHmac(
      algorithm,
      keyAsString as ArrayBuffer
    );
  }

  /**
   * Updates the `Hmac` content with the given `data`, the encoding of which
   * is given in `inputEncoding`.
   * If `encoding` is not provided, and the `data` is a string, an
   * encoding of `'utf8'` is enforced. If `data` is a `Buffer`, `TypedArray`, or`DataView`, then `inputEncoding` is ignored.
   *
   * This can be called many times with new data as it is streamed.
   * @since v0.1.94
   * @param inputEncoding The `encoding` of the `data` string.
   */
  update(data: string | BinaryLike, inputEncoding?: Encoding): Hmac {
    if (data instanceof ArrayBuffer) {
      this.internalHmac.update(data);
      return this;
    }
    if (typeof data === 'string') {
      const buffer = Buffer.from(data, inputEncoding);
      this.internalHmac.update(toArrayBuffer(buffer));
      return this;
    }

    this.internalHmac.update(binaryLikeToArrayBuffer(data));
    return this;
  }

  _transform(
    chunk: string | BinaryLike,
    encoding: Encoding,
    callback: () => void
  ) {
    this.update(chunk, encoding);
    callback();
  }

  _flush(callback: () => void) {
    this.push(this.digest());
    callback();
  }

  /**
   * Calculates the HMAC digest of all of the data passed using `hmac.update()`.
   * If `encoding` is
   * provided a string is returned; otherwise a `Buffer` is returned;
   *
   * The `Hmac` object can not be used again after `hmac.digest()` has been
   * called. Multiple calls to `hmac.digest()` will result in an error being thrown.
   * @since v0.1.94
   * @param encoding The `encoding` of the return value.
   */
  digest(): Buffer;
  digest(encoding: 'buffer'): Buffer;
  digest(encoding: Encoding): string;
  digest(encoding?: Encoding | 'buffer'): string | Buffer {
    const result: ArrayBuffer = this.isFinalized
      ? new ArrayBuffer(0)
      : this.internalHmac.digest();
    this.isFinalized = true;
    if (encoding && encoding !== 'buffer') {
      return Buffer.from(result).toString(encoding);
    }
    return Buffer.from(result);
  }
}
