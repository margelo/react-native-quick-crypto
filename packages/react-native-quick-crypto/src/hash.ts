import { Stream } from 'readable-stream';
import { NitroModules } from 'react-native-nitro-modules';
import type { TransformOptions } from 'readable-stream';
import type { Hash as NativeHash } from './specs/hash.nitro';
import type { HashAlgorithm } from './utils';

interface HashArgs {
  algorithm: HashAlgorithm;
  options: Record<string, TransformOptions>;
}

class Hash extends Stream.Transform {
  private native: NativeHash;

  constructor({ options }: HashArgs) {
    super(options);
    this.native = NitroModules.createHybridObject<NativeHash>('Hash');
    console.log(`${this.native.name} created`);
  }
}

export function createHash(
  algorithm: HashAlgorithm,
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
