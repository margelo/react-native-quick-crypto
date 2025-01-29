import { Stream } from 'readable-stream';
import { NitroModules } from 'react-native-nitro-modules';
import type { TransformOptions } from 'readable-stream';
import type { Hash as NativeHash } from './specs/hash.nitro';
import type { BinaryLike, BinaryToTextEncoding, Encoding } from './utils';
import { binaryLikeToArrayBuffer } from './utils';

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
  update(data: BinaryLike, _inputEncoding?: Encoding): Hash;
  update(data: BinaryLike): Hash {
    this.native.update(binaryLikeToArrayBuffer(data));
    return this;
  }

  /**
   * TODO: docs
   */
  digest(encoding?: BinaryToTextEncoding): string {
    return this.native.digest(encoding);
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
