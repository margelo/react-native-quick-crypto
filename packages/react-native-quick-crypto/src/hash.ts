import { Stream } from 'readable-stream';
import { NitroModules } from 'react-native-nitro-modules';
import type { TransformOptions } from 'readable-stream';
import type { Hash as NativeHash } from './specs/hash.nitro';
import type { BinaryLike, BinaryToTextEncoding, Encoding } from './utils';
import { ab2str, binaryLikeToArrayBuffer } from './utils';
import { normalizeEncoding, validateEncoding } from './utils/cipher';

interface HashArgs {
  algorithm: string;
  options: Record<string, TransformOptions>;
}

class Hash extends Stream.Transform {
  private native: NativeHash;

  /**
   * TODO: docs
   */
  constructor({ algorithm, options }: HashArgs) {
    super(options);
    this.native = NitroModules.createHybridObject<NativeHash>('Hash');
    this.native.createHash(algorithm);
  }

  /**
   * TODO: docs
   */
  update(data: BinaryLike): Hash;
  update(data: BinaryLike, inputEncoding: Encoding): Buffer;
  update(data: BinaryLike, inputEncoding?: Encoding): Hash | Buffer {
    const defaultEncoding: Encoding = 'utf-8';
    inputEncoding = inputEncoding ?? defaultEncoding;

    if (typeof data === 'string') {
      validateEncoding(data, inputEncoding);
    } else if (!ArrayBuffer.isView(data)) {
      throw new Error('Invalid data argument');
    }

    // TODO: should this return a buffer?
    this.native.update(binaryLikeToArrayBuffer(data, inputEncoding));

    if (typeof data === 'string' && inputEncoding !== 'buffer') {
      // to support chaining syntax createHash().update().digest()
      return this;
    }

    return Buffer.from([]); // returning empty buffer as _flush calls digest
  }

  /**
   * TODO: docs
   */
  digest(): Buffer;
  digest(encoding: 'buffer'): Buffer;
  digest(encoding: BinaryToTextEncoding): string;
  digest(encoding?: BinaryToTextEncoding | 'buffer'): Buffer | string {
    const nativeDigest = this.native.digest(encoding);

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
    this.push(this.update(chunk, normalizeEncoding(encoding)));
    callback();
  }
  _flush(callback: () => void) {
    this.push(this.digest());
    callback();
  }
}

export function createHash(
  algorithm: string,
  options?: TransformOptions,
): Hash {
  return new Hash({
    algorithm,
    options: options as Record<string, TransformOptions>,
  });
}

export const hashExports = {
  createHash,
};
