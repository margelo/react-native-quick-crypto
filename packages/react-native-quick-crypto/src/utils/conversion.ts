import { Buffer as CraftzdogBuffer } from '@craftzdog/react-native-buffer';
import { Buffer as SafeBuffer } from 'safe-buffer';
import type { ABV, BinaryLikeNode, BufferLike } from './types';

/**
 * Converts supplied argument to an ArrayBuffer.  Note this does not copy the
 * data so it is faster than toArrayBuffer.  Not copying is important for
 * functions like randomFill which need to be able to write to the underlying
 * buffer.
 * @param buf
 * @returns ArrayBuffer
 */
export const abvToArrayBuffer = (buf: ABV) => {
  if (CraftzdogBuffer.isBuffer(buf)) {
    return buf.buffer as ArrayBuffer;
  }
  if (ArrayBuffer.isView(buf)) {
    return buf.buffer as ArrayBuffer;
  }
  return buf as ArrayBuffer;
};

/**
 * Converts supplied argument to an ArrayBuffer.  Note this copies data if the
 * supplied buffer has the .slice() method, so can be a bit slow.
 * @param buf
 * @returns ArrayBuffer
 */
export function toArrayBuffer(
  buf: CraftzdogBuffer | SafeBuffer | ArrayBufferView,
): ArrayBuffer {
  if (CraftzdogBuffer.isBuffer(buf) || ArrayBuffer.isView(buf)) {
    if (buf?.buffer?.slice) {
      return buf.buffer.slice(
        buf.byteOffset,
        buf.byteOffset + buf.byteLength,
      ) as ArrayBuffer;
    } else {
      return buf.buffer as ArrayBuffer;
    }
  }
  const ab = new ArrayBuffer(buf.length);
  const view = new Uint8Array(ab);
  for (let i = 0; i < buf.length; ++i) {
    view[i] = SafeBuffer.isBuffer(buf) ? buf.readUInt8(i) : buf[i]!;
  }
  return ab;
}

export function bufferLikeToArrayBuffer(buf: BufferLike): ArrayBuffer {
  // Buffer
  if (CraftzdogBuffer.isBuffer(buf) || SafeBuffer.isBuffer(buf)) {
    return toArrayBuffer(buf);
  }
  // ArrayBufferView
  if (ArrayBuffer.isView(buf)) {
    return toArrayBuffer(buf);
  }

  // If buf is already an ArrayBuffer, return it.
  if (buf instanceof ArrayBuffer) {
    return buf;
  }

  // If buf is a SharedArrayBuffer, convert it to ArrayBuffer.
  // This typically involves a copy of the data.
  if (
    typeof SharedArrayBuffer !== 'undefined' &&
    buf instanceof SharedArrayBuffer
  ) {
    const arrayBuffer = new ArrayBuffer(buf.byteLength);
    new Uint8Array(arrayBuffer).set(new Uint8Array(buf));
    return arrayBuffer;
  }

  // If we reach here, 'buf' is of a type within BufferLike that has not been handled by the above checks.
  // This indicates either an incomplete BufferLike definition or an unexpected input type.
  // Throw an error to signal this, ensuring the function's contract (return ArrayBuffer or throw) is met.
  throw new TypeError(
    'Input must be a Buffer, ArrayBufferView, ArrayBuffer, or SharedArrayBuffer.',
  );
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

    const buffer = CraftzdogBuffer.from(input, encoding);

    return buffer.buffer.slice(
      buffer.byteOffset,
      buffer.byteOffset + buffer.byteLength,
    );
  }

  // Buffer
  if (CraftzdogBuffer.isBuffer(input) || SafeBuffer.isBuffer(input)) {
    return toArrayBuffer(input);
  }

  // ArrayBufferView
  // TODO add further binary types to BinaryLike, UInt8Array and so for have this array as property
  if (ArrayBuffer.isView(input)) {
    return toArrayBuffer(input);
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
  return CraftzdogBuffer.from(buf).toString(encoding);
}

export const kEmptyObject = Object.freeze(Object.create(null));
