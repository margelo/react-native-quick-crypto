import { NativeFastCrypto } from './NativeFastCrypto/NativeFastCrypto';
import { Buffer } from '@craftzdog/react-native-buffer';

const random = NativeFastCrypto.random;

export function randomFill(
  buffer: ArrayBuffer,
  callback: (err: Error | null, buf?: ArrayBuffer) => void
): void;

export function randomFill(
  buffer: ArrayBuffer,
  offset: number,
  callback: (err: Error | null, buf?: ArrayBuffer) => void
): void;

export function randomFill(
  buffer: ArrayBuffer,
  offset: number,
  size: number,
  callback: (err: Error | null, buf?: ArrayBuffer) => void
): void;

export function randomFill(buffer: ArrayBuffer, ...rest: any[]): void {
  if (typeof rest[rest.length - 1] !== 'function') {
    throw new Error('No callback provided to randomDill');
  }

  const callback = rest[rest.length - 1] as any as (
    err: Error | null,
    buf?: ArrayBuffer
  ) => void;

  let offset: number = 0;
  let size: number = buffer.byteLength;

  if (typeof rest[2] === 'function') {
    offset = rest[0];
    size = rest[1];
  }

  if (typeof rest[1] === 'function') {
    offset = rest[0];
  }

  random.randomFill(buffer, offset, size).then(
    () => {
      callback(null, buffer);
    },
    (e: Error) => {
      callback(e);
    }
  );
}

export function randomFillSync(
  buffer: ArrayBuffer,
  offset: number = 0,
  size?: number
) {
  random.randomFillSync(buffer, offset, size ?? buffer.byteLength);
  return buffer;
}

export function randomBytes(size: number): ArrayBuffer;

export function randomBytes(
  size: number,
  callback: (err: Error | null, buf?: ArrayBuffer) => void
): void;

export function randomBytes(
  size: number,
  callback?: (err: Error | null, buf?: ArrayBuffer) => void
): void | ArrayBuffer {
  const buf = new Buffer(size);

  if (callback === undefined) {
    randomFillSync(buf.buffer, 0, size);
    return buf;
  }

  randomFill(buf.buffer, 0, size, (error: Error | null) => {
    if (error) {
      callback(error);
    }
    callback(null, buf);
  });
}
