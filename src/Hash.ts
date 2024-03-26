/* eslint-disable no-dupe-class-members */
import 'react-native';
import { NativeQuickCrypto } from './NativeQuickCrypto/NativeQuickCrypto';
import type { InternalHash } from './NativeQuickCrypto/hash';
import {
  type Encoding,
  toArrayBuffer,
  validateMaxBufferLength,
  normalizeHashName,
  type BufferLike,
  bufferLikeToArrayBuffer,
} from './Utils';
import Stream from 'stream-browserify';
import { Buffer } from '@craftzdog/react-native-buffer';
import { lazyDOMException } from './Utils';
import type { SubtleAlgorithm } from './keys';

interface HashOptionsBase extends Stream.TransformOptions {
  outputLength?: number | undefined;
}

type HashOptions = null | undefined | HashOptionsBase;

global.process.nextTick = setImmediate;

const createInternalHash = NativeQuickCrypto.createHash;

export function createHash(algorithm: string, options?: HashOptions) {
  return new Hash(algorithm, options);
}

class Hash extends Stream.Transform {
  private internalHash: InternalHash;

  constructor(other: Hash, options?: HashOptions);
  constructor(algorithm: string, options?: HashOptions);
  constructor(arg: string | Hash, options?: HashOptions) {
    super(options ?? undefined);
    if (arg instanceof Hash) {
      this.internalHash = arg.internalHash.copy(options?.outputLength);
    } else {
      this.internalHash = createInternalHash(arg, options?.outputLength);
    }
  }

  copy(options?: HashOptionsBase): Hash {
    const copy = new Hash(this, options);
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
  update(data: string | ArrayBuffer, inputEncoding?: Encoding): Hash {
    if (data instanceof ArrayBuffer) {
      this.internalHash.update(data);
      return this;
    }
    const buffer = Buffer.from(data, inputEncoding);
    this.internalHash.update(toArrayBuffer(buffer));
    return this;
  }

  _transform(
    chunk: string | ArrayBuffer,
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
  digest(encoding: 'buffer'): Buffer;
  digest(encoding: Encoding): string;
  digest(encoding?: Encoding | 'buffer'): string | Buffer {
    const result: ArrayBuffer = this.internalHash.digest();

    if (encoding && encoding !== 'buffer') {
      return Buffer.from(result).toString(encoding);
    }

    return Buffer.from(result);
  }
}

// Implementation for WebCrypto subtle.digest()

export const asyncDigest = async (
  algorithm: SubtleAlgorithm,
  data: BufferLike
): Promise<ArrayBuffer> => {
  validateMaxBufferLength(data, 'data');

  switch (algorithm.name) {
    case 'SHA-1':
    // Fall through
    case 'SHA-256':
    // Fall through
    case 'SHA-384':
    // Fall through
    case 'SHA-512':
      const normalizedHashName = normalizeHashName(algorithm.name);
      const hash = new Hash(normalizedHashName);
      hash.update(bufferLikeToArrayBuffer(data));
      return hash.digest();
  }

  throw lazyDOMException(
    `Unrecognized algorithm name: ${algorithm.name}`,
    'NotSupportedError'
  );
};
