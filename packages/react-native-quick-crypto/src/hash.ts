import { Stream } from 'readable-stream';
import { NitroModules } from 'react-native-nitro-modules';
import type { TransformOptions } from 'readable-stream';
import { Buffer } from '@craftzdog/react-native-buffer';
import type { Hash as NativeHash } from './specs/hash.nitro';
import type { TurboShake as NativeTurboShake } from './specs/turboshake.nitro';
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
  digest(encoding: Encoding): string;
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

  // Stream interface — surface synchronous errors via the callback so
  // they emit as stream 'error' events instead of throwing out of the
  // Transform plumbing (which would crash the host pipeline).
  _transform(
    chunk: BinaryLike,
    encoding: BufferEncoding,
    callback: (err?: Error | null) => void,
  ) {
    try {
      this.update(chunk, encoding as Encoding);
      callback();
    } catch (err) {
      callback(err as Error);
    }
  }
  _flush(callback: (err?: Error | null) => void) {
    try {
      this.push(this.digest());
      callback();
    } catch (err) {
      callback(err as Error);
    }
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
    // CShakeParams.outputLength is required (in bits) per the WICG modern-algos
    // spec, renamed from `length` (commit ab8dc2b84c2). Mirror Node's
    // hash.js:223-228 / webidl.js:570-595.
    if (
      typeof algorithm.outputLength !== 'number' ||
      algorithm.outputLength <= 0
    ) {
      throw lazyDOMException(
        'CShakeParams.outputLength is required',
        'OperationError',
      );
    }
    if (algorithm.outputLength % 8) {
      throw lazyDOMException(
        'Unsupported CShakeParams outputLength',
        'NotSupportedError',
      );
    }
    return internalDigest(algorithm, data, algorithm.outputLength / 8);
  }

  if (name === 'TurboSHAKE128' || name === 'TurboSHAKE256') {
    return turboShakeDigest(name, algorithm, data);
  }

  if (name === 'KT128' || name === 'KT256') {
    return kangarooTwelveDigest(name, algorithm, data);
  }

  throw lazyDOMException(
    `Unrecognized algorithm name: ${name}`,
    'NotSupportedError',
  );
};

// TurboSHAKE / KangarooTwelve are not exposed by OpenSSL EVP, so we route
// them to a dedicated Nitro module (cpp/turboshake) that ports the Node.js
// reference implementation. Lazy-load to keep the module out of the hot path
// for callers that only use SHA-2/SHA-3.
let nativeTurboShake: NativeTurboShake | undefined;
const getTurboShake = (): NativeTurboShake => {
  if (!nativeTurboShake) {
    nativeTurboShake =
      NitroModules.createHybridObject<NativeTurboShake>('TurboShake');
  }
  return nativeTurboShake;
};

// RFC 9861 §2.2 default per the WICG Modern Algos draft for TurboSHAKE.
const kDefaultTurboShakeDomainSeparation = 0x1f;

const turboShakeDigest = async (
  name: 'TurboSHAKE128' | 'TurboSHAKE256',
  algorithm: SubtleAlgorithm,
  data: BufferLike,
): Promise<ArrayBuffer> => {
  if (
    typeof algorithm.outputLength !== 'number' ||
    algorithm.outputLength <= 0
  ) {
    throw lazyDOMException(
      'TurboShakeParams.outputLength is required',
      'OperationError',
    );
  }
  if (algorithm.outputLength % 8) {
    throw lazyDOMException(
      'Invalid TurboShakeParams outputLength',
      'OperationError',
    );
  }
  const ds = algorithm.domainSeparation ?? kDefaultTurboShakeDomainSeparation;
  if (
    typeof ds !== 'number' ||
    !Number.isInteger(ds) ||
    ds < 0x01 ||
    ds > 0x7f
  ) {
    throw lazyDOMException(
      'TurboShakeParams.domainSeparation must be in range 0x01-0x7f',
      'OperationError',
    );
  }
  return getTurboShake().turboShake(
    name,
    ds,
    algorithm.outputLength / 8,
    bufferLikeToArrayBuffer(data),
  );
};

const kangarooTwelveDigest = async (
  name: 'KT128' | 'KT256',
  algorithm: SubtleAlgorithm,
  data: BufferLike,
): Promise<ArrayBuffer> => {
  if (
    typeof algorithm.outputLength !== 'number' ||
    algorithm.outputLength <= 0
  ) {
    throw lazyDOMException(
      'KangarooTwelveParams.outputLength is required',
      'OperationError',
    );
  }
  if (algorithm.outputLength % 8) {
    throw lazyDOMException(
      'Invalid KangarooTwelveParams outputLength',
      'OperationError',
    );
  }
  const customization =
    algorithm.customization !== undefined
      ? bufferLikeToArrayBuffer(algorithm.customization)
      : undefined;
  return getTurboShake().kangarooTwelve(
    name,
    algorithm.outputLength / 8,
    bufferLikeToArrayBuffer(data),
    customization,
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
  outputEncoding: Encoding,
): string;
export function hash(algorithm: string, data: BinaryLike): Buffer;
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
