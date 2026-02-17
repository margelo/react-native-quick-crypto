import { Stream } from 'readable-stream';
import { NitroModules } from 'react-native-nitro-modules';
import type { TransformOptions } from 'readable-stream';
import type { Hash as NativeHash } from './specs/hash.nitro';
import type {
  BinaryLike,
  Encoding,
  BufferLike,
  SubtleAlgorithm,
} from './utils';
import {
  ab2str,
  binaryLikeToArrayBuffer,
  bufferLikeToArrayBuffer,
} from './utils';
import { validateMaxBufferLength } from './utils/validation';
import { lazyDOMException } from './utils/errors';
import { normalizeHashName } from './utils/hashnames';

class HashUtils {
  private static native = NitroModules.createHybridObject<NativeHash>('Hash');
  public static getSupportedHashAlgorithms(): string[] {
    return this.native.getSupportedHashAlgorithms();
  }
}

export function getHashes() {
  return HashUtils.getSupportedHashAlgorithms();
}

interface HashOptions extends TransformOptions {
  /**
   * For XOF hash functions such as `shake256`, the
   * outputLength option can be used to specify the desired output length in bytes.
   */
  outputLength?: number | undefined;
}

interface HashArgs {
  algorithm: string;
  options?: HashOptions;
  native?: NativeHash;
}

class Hash extends Stream.Transform {
  private algorithm: string;
  private options: HashOptions;
  private native: NativeHash;

  private validate(args: HashArgs) {
    if (typeof args.algorithm !== 'string' || args.algorithm.length === 0)
      throw new Error('Algorithm must be a non-empty string');
    if (
      args.options?.outputLength !== undefined &&
      args.options.outputLength < 0
    )
      throw new Error('Output length must be a non-negative number');
    if (
      args.options?.outputLength !== undefined &&
      typeof args.options.outputLength !== 'number'
    )
      throw new Error('Output length must be a number');
  }

  /**
   * @internal use `createHash()` instead
   */
  private constructor(args: HashArgs) {
    super(args.options);

    this.validate(args);

    this.algorithm = args.algorithm;
    this.options = args.options ?? {};

    if (args.native) {
      this.native = args.native;
      return;
    }

    this.native = NitroModules.createHybridObject<NativeHash>('Hash');
    this.native.createHash(this.algorithm, this.options.outputLength);
  }

  /**
   * Updates the hash content with the given `data`, the encoding of which
   * is given in `inputEncoding`.
   * If `encoding` is not provided, and the `data` is a string, an
   * encoding of `'utf8'` is enforced. If `data` is a `Buffer`, `TypedArray`, or`DataView`, then `inputEncoding` is ignored.
   *
   * This can be called many times with new data as it is streamed.
   * @since v1.0.0
   * @param inputEncoding The `encoding` of the `data` string.
   */
  update(data: BinaryLike): Hash;
  update(data: BinaryLike, inputEncoding: Encoding): Buffer;
  update(data: BinaryLike, inputEncoding?: Encoding): Hash | Buffer {
    const defaultEncoding: Encoding = 'utf8';
    inputEncoding = inputEncoding ?? defaultEncoding;

    // OPTIMIZED PATH: Pass UTF-8 strings directly to native without conversion
    if (typeof data === 'string' && inputEncoding === 'utf8') {
      this.native.update(data);
    } else {
      this.native.update(binaryLikeToArrayBuffer(data, inputEncoding));
    }

    return this; // to support chaining syntax createHash().update().digest()
  }

  /**
   * Calculates the digest of all of the data passed to be hashed (using the `hash.update()` method).
   * If `encoding` is provided a string will be returned; otherwise
   * a `Buffer` is returned.
   *
   * The `Hash` object can not be used again after `hash.digest()` method has been
   * called. Multiple calls will cause an error to be thrown.
   * @since v1.0.0
   * @param encoding The `encoding` of the return value.
   */
  digest(): Buffer;
  digest(encoding: Encoding): Buffer;
  digest(encoding?: Encoding): Buffer | string {
    const nativeDigest = this.native.digest(encoding);

    if (encoding && encoding !== 'buffer') {
      return ab2str(nativeDigest, encoding);
    }

    return Buffer.from(nativeDigest);
  }

  /**
   * Creates a new `Hash` object that contains a deep copy of the internal state
   * of the current `Hash` object.
   *
   * The optional `options` argument controls stream behavior. For XOF hash
   * functions such as `'shake256'`, the `outputLength` option can be used to
   * specify the desired output length in bytes.
   *
   * An error is thrown when an attempt is made to copy the `Hash` object after
   * its `hash.digest()` method has been called.
   *
   * ```js
   * // Calculate a rolling hash.
   * import { createHash } from 'react-native-quick-crypto';
   *
   * const hash = createHash('sha256');
   *
   * hash.update('one');
   * console.log(hash.copy().digest('hex'));
   *
   * hash.update('two');
   * console.log(hash.copy().digest('hex'));
   *
   * hash.update('three');
   * console.log(hash.copy().digest('hex'));
   *
   * // Etc.
   * ```
   * @since v1.0.0
   * @param options `stream.transform` options
   */
  copy(): Hash;
  copy(options: HashOptions): Hash;
  copy(options?: HashOptions): Hash {
    const newOptions = options ?? this.options;
    const newNativeHash = this.native.copy(newOptions.outputLength);
    const hash = new Hash({
      algorithm: this.algorithm,
      options: newOptions,
      native: newNativeHash,
    });
    return hash;
  }

  /**
   * Returns the OpenSSL version string
   * @since v1.0.0
   */
  getOpenSSLVersion(): string {
    return this.native.getOpenSSLVersion();
  }

  // stream interface
  _transform(
    chunk: BinaryLike,
    encoding: BufferEncoding,
    callback: () => void,
  ) {
    this.update(chunk, encoding as Encoding);
    callback();
  }
  _flush(callback: () => void) {
    this.push(this.digest());
    callback();
  }
}

/**
 * Creates and returns a `Hash` object that can be used to generate hash digests
 * using the given `algorithm`. Optional `options` argument controls stream
 * behavior. For XOF hash functions such as `'shake256'`, the `outputLength` option
 * can be used to specify the desired output length in bytes.
 *
 * The `algorithm` is dependent on the available algorithms supported by the
 * version of OpenSSL on the platform. Examples are `'sha256'`, `'sha512'`, etc.
 * On recent releases of OpenSSL, `openssl list -digest-algorithms` will
 * display the available digest algorithms.
 *
 * Example: generating the sha256 sum of a file
 *
 * ```js
 * import crypto from 'react-native-quick-crypto';
 *
 * const hash = crypto.createHash('sha256').update('Test123').digest('hex');
 * console.log('SHA-256 of "Test123":', hash);
 * ```
 * @since v1.0.0
 * @param options `stream.transform` options
 */
export function createHash(algorithm: string, options?: HashOptions): Hash {
  // @ts-expect-error private constructor
  return new Hash({
    algorithm,
    options,
  });
}

// Implementation for WebCrypto subtle.digest()

/**
 * Asynchronous digest function for WebCrypto SubtleCrypto API
 * @param algorithm The hash algorithm to use
 * @param data The data to hash
 * @returns Promise resolving to the hash digest as ArrayBuffer
 */
export const asyncDigest = async (
  algorithm: SubtleAlgorithm,
  data: BufferLike,
): Promise<ArrayBuffer> => {
  validateMaxBufferLength(data, 'data');

  const name = algorithm.name;

  if (
    name === 'SHA-1' ||
    name === 'SHA-256' ||
    name === 'SHA-384' ||
    name === 'SHA-512' ||
    name === 'SHA3-256' ||
    name === 'SHA3-384' ||
    name === 'SHA3-512'
  ) {
    return internalDigest(algorithm, data);
  }

  if (name === 'cSHAKE128' || name === 'cSHAKE256') {
    if (typeof algorithm.length !== 'number' || algorithm.length <= 0) {
      throw lazyDOMException(
        'cSHAKE requires a length parameter',
        'OperationError',
      );
    }
    if (algorithm.length % 8) {
      throw lazyDOMException(
        'Unsupported CShakeParams length',
        'NotSupportedError',
      );
    }
    return internalDigest(algorithm, data, algorithm.length);
  }

  throw lazyDOMException(
    `Unrecognized algorithm name: ${name}`,
    'NotSupportedError',
  );
};

const internalDigest = (
  algorithm: SubtleAlgorithm,
  data: BufferLike,
  outputLength?: number,
): ArrayBuffer => {
  const normalizedHashName = normalizeHashName(algorithm.name);
  const hash = createHash(
    normalizedHashName,
    outputLength ? { outputLength } : undefined,
  );
  hash.update(bufferLikeToArrayBuffer(data));
  const result = hash.digest();
  const arrayBuffer = new ArrayBuffer(result.length);
  const view = new Uint8Array(arrayBuffer);
  view.set(result);
  return arrayBuffer;
};

export function hash(
  algorithm: string,
  data: BinaryLike,
  outputEncoding?: Encoding,
): string | Buffer {
  const h = createHash(algorithm);
  h.update(data);
  return outputEncoding ? h.digest(outputEncoding) : h.digest();
}

export const hashExports = {
  createHash,
  getHashes,
  hash,
  asyncDigest,
};
