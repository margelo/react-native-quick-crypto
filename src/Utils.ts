import { Buffer } from '@craftzdog/react-native-buffer';

export type BinaryLike = string | ArrayBuffer | Buffer;

export type BinaryToTextEncoding = 'base64' | 'base64url' | 'hex' | 'binary';
export type CharacterEncoding = 'utf8' | 'utf-8' | 'utf16le' | 'latin1';
export type LegacyCharacterEncoding = 'ascii' | 'binary' | 'ucs2' | 'ucs-2';
export type Encoding =
  | BinaryToTextEncoding
  | CharacterEncoding
  | LegacyCharacterEncoding;

export function isBuffer(buf: any): buf is Buffer {
  return buf instanceof Buffer || buf?.constructor?.name === 'Buffer';
}

export function toArrayBuffer(buf: Buffer): ArrayBuffer {
  if (buf?.buffer?.slice) {
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }
  const ab = new ArrayBuffer(buf.length);
  const view = new Uint8Array(ab);
  for (let i = 0; i < buf.length; ++i) {
    view[i] = buf[i];
  }
  return ab;
}

export function binaryLikeToArrayBuffer(input: BinaryLike): ArrayBuffer {
  if (typeof input === 'string') {
    const buffer = Buffer.from(input, 'utf-8');
    return buffer.buffer.slice(
      buffer.byteOffset,
      buffer.byteOffset + buffer.byteLength
    );
  }

  if (isBuffer(input)) {
    return toArrayBuffer(input);
  }

  if ((input as any).buffer) {
    return (input as any).buffer;
  }

  if (!(input instanceof ArrayBuffer)) {
    try {
      const buffer = Buffer.from(input);
      return buffer.buffer.slice(
        buffer.byteOffset,
        buffer.byteOffset + buffer.byteLength
      );
    } catch {
      throw 'error';
    }
  }
  return input;
}

export function ab2str(buf: ArrayBuffer) {
  return Buffer.from(buf).toString('hex');
}
