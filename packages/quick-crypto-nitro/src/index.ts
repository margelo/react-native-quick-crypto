import { Buffer } from 'buffer';
import { Hash as NativeHash } from './Hash.nitro';

type HashEncoding = NonNullable<Parameters<Buffer['toString']>[0]>;

class Hash {
  private readonly native: NativeHash;

  constructor(algorithm: string) {
    this.native = new NativeHash(algorithm);
  }

  update(data: string | ArrayBufferView, inputEncoding?: HashEncoding): this {
    let bytes: ArrayBufferView;
    if (typeof data === 'string') {
      bytes = Buffer.from(data, inputEncoding);
    } else if (ArrayBuffer.isView(data)) {
      bytes = data;
    } else {
      throw new TypeError('Expected a string, TypedArray, or DataView');
    }

    const { buffer, byteOffset, byteLength } = bytes;
    if (
      buffer instanceof ArrayBuffer &&
      byteOffset === 0 &&
      byteLength === buffer.byteLength
    ) {
      this.native.update(buffer);
    } else {
      const view = new Uint8Array(buffer, byteOffset, byteLength);
      const copy = new Uint8Array(view);
      this.native.update(copy.buffer);
    }
    return this;
  }

  digest(): Buffer;
  digest(encoding: HashEncoding): string;
  digest(encoding?: HashEncoding): Buffer | string {
    const raw = this.native.digest();
    const bytes = Buffer.from(raw);
    if (encoding === undefined) return bytes;
    return bytes.toString(encoding);
  }
}

/** Creates an incremental fixed-length hash. */
export function createHash(algorithm: string, options?: never): Hash {
  if (options !== undefined) {
    throw new TypeError('Hash options are not supported');
  }
  return new Hash(algorithm);
}

export default { createHash: createHash };
