import { NitroModules } from 'react-native-nitro-modules';
import { Buffer } from '@craftzdog/react-native-buffer';
import type { Blake3 as NativeBlake3 } from './specs/blake3.nitro';
import type { BinaryLike, Encoding } from './utils';
import { binaryLikeToArrayBuffer, ab2str } from './utils';

const BLAKE3_KEY_LEN = 32;
const BLAKE3_OUT_LEN = 32;

export interface Blake3Options {
  dkLen?: number;
  key?: Uint8Array;
  context?: string;
}

export class Blake3 {
  private native: NativeBlake3;
  private mode: 'hash' | 'keyed' | 'deriveKey';
  private keyData?: Uint8Array;
  private contextData?: string;

  constructor(opts?: Blake3Options) {
    this.native = NitroModules.createHybridObject<NativeBlake3>('Blake3');

    if (opts?.key && opts?.context) {
      throw new Error(
        'BLAKE3: cannot use both key and context options together',
      );
    }

    if (opts?.key) {
      if (opts.key.length !== BLAKE3_KEY_LEN) {
        throw new Error(`BLAKE3: key must be exactly ${BLAKE3_KEY_LEN} bytes`);
      }
      this.mode = 'keyed';
      this.keyData = opts.key;
      this.native.initKeyed(opts.key.buffer as ArrayBuffer);
    } else if (opts?.context !== undefined) {
      if (typeof opts.context !== 'string' || opts.context.length === 0) {
        throw new Error('BLAKE3: context must be a non-empty string');
      }
      this.mode = 'deriveKey';
      this.contextData = opts.context;
      this.native.initDeriveKey(opts.context);
    } else {
      this.mode = 'hash';
      this.native.initHash();
    }
  }

  update(data: BinaryLike, inputEncoding?: Encoding): this {
    const buffer = binaryLikeToArrayBuffer(data, inputEncoding ?? 'utf8');
    this.native.update(buffer);
    return this;
  }

  digest(): Buffer;
  digest(encoding: Encoding): string;
  digest(length: number): Buffer;
  digest(encodingOrLength?: Encoding | number): Buffer | string {
    let length: number | undefined;
    let encoding: Encoding | undefined;

    if (typeof encodingOrLength === 'number') {
      length = encodingOrLength;
    } else if (encodingOrLength) {
      encoding = encodingOrLength;
    }

    const result = this.native.digest(length);

    if (encoding && encoding !== 'buffer') {
      return ab2str(result, encoding);
    }

    return Buffer.from(result);
  }

  digestLength(length: number): Buffer {
    return Buffer.from(this.native.digest(length));
  }

  reset(): this {
    this.native.reset();
    return this;
  }

  copy(): Blake3 {
    const copied = new Blake3();
    // Replace the native with a copy
    copied.native = this.native.copy() as NativeBlake3;
    copied.mode = this.mode;
    copied.keyData = this.keyData;
    copied.contextData = this.contextData;
    return copied;
  }

  static getVersion(): string {
    const native = NitroModules.createHybridObject<NativeBlake3>('Blake3');
    native.initHash();
    return native.getVersion();
  }
}

export function createBlake3(opts?: Blake3Options): Blake3 {
  return new Blake3(opts);
}

export function blake3(data: BinaryLike, opts?: Blake3Options): Uint8Array {
  const hasher = new Blake3(opts);
  hasher.update(data);
  const length = opts?.dkLen ?? BLAKE3_OUT_LEN;
  const result = hasher.digestLength(length);
  return new Uint8Array(result);
}

blake3.create = createBlake3;

export const blake3Exports = {
  Blake3,
  createBlake3,
  blake3,
};
