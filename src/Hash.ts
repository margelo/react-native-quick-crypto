import { NativeFastCrypto } from './NativeFastCrypto/NativeFastCrypto';
import type { InternalHash } from './NativeFastCrypto/hash';
import { BinaryToTextEncoding, Encoding, toArrayBuffer } from './Utils';
import Stream from 'stream';
import { Buffer } from '@craftzdog/react-native-buffer';
interface HashOptions extends Stream.TransformOptions {
  outputLength?: number | undefined;
}

const createInternalHash = NativeFastCrypto.createHash;

type BinaryLike = ArrayBuffer;

export function createHash(algorithm: string, options?: HashOptions) {
  return new Hash(algorithm, options);
}

class Hash extends Stream.Transform {
  private internalHash: InternalHash;
  private options?: Stream.TransformOptions;

  constructor(other: Hash, options?: HashOptions);
  constructor(algorithm: string, options?: HashOptions);
  constructor(arg: string | Hash, options?: HashOptions) {
    super(options);
    if (arg instanceof Hash) {
      this.internalHash = arg.internalHash.copy(options?.outputLength);
    } else {
      this.internalHash = createInternalHash(arg, options?.outputLength);
    }
    this.options = options;
  }

  copy(options?: Stream.TransformOptions): Hash {
    const copy = new Hash(this, options);
    copy.options = options;
    return copy;
  }
  /**
   * Updates the hash content with the given `data`, the encoding of which
   * is given in `inputEncoding`.
   * If `encoding` is not provided, and the `data` is a string, an
   * encoding of `'utf8'` is enforced. If `data` is a `Buffer`, `TypedArray`, or`DataView`, then `inputEncoding` is ignored.
   *
   * This can be called many times with new data as it is streamed.
   * @since v0.1.92
   * @param inputEncoding The `encoding` of the `data` string.
   */
  update(data: string | BinaryLike, inputEncoding?: Encoding): Hash {
    if (data instanceof ArrayBuffer) {
      this.internalHash.update(data);
      return this;
    }
    const buffer = Buffer.from(data, inputEncoding);
    this.internalHash.update(toArrayBuffer(buffer));
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
   * Calculates the digest of all of the data passed to be hashed (using the `hash.update()` method).
   * If `encoding` is provided a string will be returned; otherwise
   * a `Buffer` is returned.
   *
   * The `Hash` object can not be used again after `hash.digest()` method has been
   * called. Multiple calls will cause an error to be thrown.
   * @since v0.1.92
   * @param encoding The `encoding` of the return value.
   */
  digest(): Buffer;
  digest(encoding: BinaryToTextEncoding): string;
  digest(encoding: BinaryToTextEncoding | undefined): string | Buffer {
    const result: ArrayBuffer = this.internalHash.digest();
    if (encoding && encoding !== 'buffer') {
      return Buffer.from(result).toString(encoding);
    }
    return Buffer.from(result);
  }

}

console.log('prop', new Hash('sha512').end('df'));
