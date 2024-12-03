import { Buffer } from '@craftzdog/react-native-buffer';
import { Buffer as SBuffer } from 'safe-buffer';
import type { ArrayBufferView, BinaryLikeNode, BufferLike } from './types';

export const abvToArrayBuffer = (buffer: ArrayBufferView) => {
  if (Buffer.isBuffer(buffer)) {
    return buffer.buffer;
  }
  if (ArrayBuffer.isView(buffer)) {
    return buffer.buffer;
  }
  return buffer;
};

export function toArrayBuffer(buf: Buffer | SBuffer): ArrayBuffer {
  if (Buffer.isBuffer(buf) && buf?.buffer?.slice) {
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }
  const ab = new ArrayBuffer(buf.length);
  const view = new Uint8Array(ab);
  for (let i = 0; i < buf.length; ++i) {
    view[i] = SBuffer.isBuffer(buf) ? buf.readUInt8(i) : buf[i]!;
  }
  return ab;
}

export function bufferLikeToArrayBuffer(buf: BufferLike): ArrayBuffer {
  if (Buffer.isBuffer(buf)) {
    return buf.buffer;
  }
  if (SBuffer.isBuffer(buf)) {
    return toArrayBuffer(buf);
  }
  if (ArrayBuffer.isView(buf)) {
    return buf.buffer;
  }
  return buf;
}

export function binaryLikeToArrayBuffer(
  input: BinaryLikeNode, // CipherKey adds compat with node types
  encoding: string = 'utf-8',
): ArrayBuffer {
  // string
  if (typeof input === 'string') {
    if (encoding === 'buffer') {
      throw new Error(
        'Cannot create a buffer from a string with a buffer encoding',
      );
    }

    const buffer = Buffer.from(input, encoding);

    return buffer.buffer.slice(
      buffer.byteOffset,
      buffer.byteOffset + buffer.byteLength,
    );
  }

  // Buffer
  if (Buffer.isBuffer(input)) {
    return toArrayBuffer(input);
  }

  // ArrayBufferView
  // TODO add further binary types to BinaryLike, UInt8Array and so for have this array as property
  if (ArrayBuffer.isView(input)) {
    return input.buffer;
  }

  // ArrayBuffer
  if (input instanceof ArrayBuffer) {
    return input;
  }

  // if (!(input instanceof ArrayBuffer)) {
  //   try {
  //     // this is a strange fallback case and input is unknown at this point
  //     const buffer = Buffer.from(input as unknown as string);
  //     return buffer.buffer.slice(
  //       buffer.byteOffset,
  //       buffer.byteOffset + buffer.byteLength
  //     );
  //   } catch(e: unknown) {
  //     console.log('throwing 1');
  //     const err = e as Error;
  //     throw new Error(err.message);
  //   }
  // }

  // TODO: handle if input is KeyObject?

  throw new Error('input could not be converted to ArrayBuffer');
}

export function ab2str(buf: ArrayBuffer, encoding: string = 'hex') {
  return Buffer.from(buf).toString(encoding);
}

export const kEmptyObject = Object.freeze(Object.create(null));
