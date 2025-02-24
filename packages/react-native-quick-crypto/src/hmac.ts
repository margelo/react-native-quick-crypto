import { Buffer } from '@craftzdog/react-native-buffer';
import { Stream } from 'readable-stream';
import { NitroModules } from 'react-native-nitro-modules';
import type { TransformOptions } from 'readable-stream';
import type { Hmac as NativeHmac } from './specs/hmac.nitro';
import type { BinaryLike, Encoding } from './utils/types';
import { ab2str, binaryLikeToArrayBuffer } from './utils/conversion';

interface HmacArgs {
  algorithm: string;
  key: BinaryLike;
  options?: TransformOptions;
}

class Hmac extends Stream.Transform {
  private algorithm: string;
  private key: BinaryLike;
  private native: NativeHmac;

  private validate(args: HmacArgs) {
    if (typeof args.algorithm !== 'string' || args.algorithm.length === 0)
      throw new Error('Algorithm must be a non-empty string');
    if (args.key === null || args.key === undefined)
      throw new Error('Key must not be null or undefined');
  }

  /**
   * @internal use `createHmac()` instead
   */
  private constructor(args: HmacArgs) {
    super(args.options);

    this.validate(args);

    this.algorithm = args.algorithm;
    this.key = args.key;

    this.native = NitroModules.createHybridObject<NativeHmac>('Hmac');
    this.native.createHmac(this.algorithm, binaryLikeToArrayBuffer(this.key));
  }

  /**
   * Updates the `Hmac` content with the given `data`, the encoding of which is given in `inputEncoding`.
   * If `encoding` is not provided, and the `data` is a string, an encoding of `'utf8'` is enforced.
   * If `data` is a `Buffer`, `TypedArray`, or`DataView`, then `inputEncoding` is ignored.
   *
   * This can be called many times with new data as it is streamed.
   * @since v1.0.0
   * @param inputEncoding The `encoding` of the `data` string.
   */
  update(data: BinaryLike): Hmac;
  update(data: BinaryLike, inputEncoding: Encoding): Hmac;
  update(data: BinaryLike, inputEncoding?: Encoding): Hmac {
    const defaultEncoding: Encoding = 'utf8';
    inputEncoding = inputEncoding ?? defaultEncoding;

    this.native.update(binaryLikeToArrayBuffer(data, inputEncoding));

    return this; // to support chaining syntax createHmac().update().digest()
  }

  /**
   * Calculates the HMAC digest of all of the data passed using `hmac.update()`.
   * If `encoding` is provided a string is returned; otherwise a `Buffer` is returned;
   *
   * The `Hmac` object can not be used again after `hmac.digest()` has been
   * called. Multiple calls to `hmac.digest()` will result in an error being thrown.
   * @since v1.0.0
   * @param encoding The `encoding` of the return value.
   */
  digest(): Buffer;
  digest(encoding: Encoding): string;
  digest(encoding?: Encoding): Buffer | string {
    const nativeDigest = this.native.digest();

    if (encoding && encoding !== 'buffer') {
      return ab2str(nativeDigest, encoding);
    }

    return Buffer.from(nativeDigest);
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
 * Creates and returns an `Hmac` object that uses the given `algorithm` and `key`.
 * Optional `options` argument controls stream behavior.
 *
 * The `algorithm` is dependent on the available algorithms supported by the
 * version of OpenSSL on the platform. Examples are `'sha256'`, `'sha512'`, etc.
 * On recent releases of OpenSSL, `openssl list -digest-algorithms` will
 * display the available digest algorithms.
 *
 * Example: generating the sha256 HMAC of a file
 *
 * ```js
 * import crypto from 'react-native-quick-crypto';
 *
 * const hmac = crypto.createHmac('sha256', 'secret-key');
 * hmac.update('message to hash');
 * const digest = hmac.digest('hex');
 * console.log(digest); // prints HMAC digest in hexadecimal format
 * ```
 * @since v1.0.0
 * @param options `stream.transform` options
 */
export function createHmac(
  algorithm: string,
  key: BinaryLike,
  options?: TransformOptions,
): Hmac {
  // @ts-expect-error private constructor
  return new Hmac({
    algorithm,
    key,
    options,
  });
}

export const hmacExports = {
  createHmac,
};
