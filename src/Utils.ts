import { Buffer } from '@craftzdog/react-native-buffer';

export type BinaryLike = string | ArrayBuffer | Buffer;

export type BinaryToTextEncoding = 'base64' | 'base64url' | 'hex' | 'binary';
export type CharacterEncoding = 'utf8' | 'utf-8' | 'utf16le' | 'latin1';
export type LegacyCharacterEncoding = 'ascii' | 'binary' | 'ucs2' | 'ucs-2';
export type Encoding =
  | BinaryToTextEncoding
  | CharacterEncoding
  | LegacyCharacterEncoding;

// TODO(osp) should buffer be part of the Encoding type?
export type CipherEncoding = Encoding | 'buffer';

// Mimics node behavior for default global encoding
let defaultEncoding: CipherEncoding = 'buffer';

export function setDefaultEncoding(encoding: CipherEncoding) {
  defaultEncoding = encoding;
}

export function getDefaultEncoding(): CipherEncoding {
  return defaultEncoding;
}

// function slowCases(enc: string) {
//   switch (enc.length) {
//     case 4:
//       if (enc === 'UTF8') return 'utf8';
//       if (enc === 'ucs2' || enc === 'UCS2') return 'utf16le';
//       enc = `${enc}`.toLowerCase();
//       if (enc === 'utf8') return 'utf8';
//       if (enc === 'ucs2') return 'utf16le';
//       break;
//     case 3:
//       if (enc === 'hex' || enc === 'HEX' || `${enc}`.toLowerCase() === 'hex')
//         return 'hex';
//       break;
//     case 5:
//       if (enc === 'ascii') return 'ascii';
//       if (enc === 'ucs-2') return 'utf16le';
//       if (enc === 'UTF-8') return 'utf8';
//       if (enc === 'ASCII') return 'ascii';
//       if (enc === 'UCS-2') return 'utf16le';
//       enc = `${enc}`.toLowerCase();
//       if (enc === 'utf-8') return 'utf8';
//       if (enc === 'ascii') return 'ascii';
//       if (enc === 'ucs-2') return 'utf16le';
//       break;
//     case 6:
//       if (enc === 'base64') return 'base64';
//       if (enc === 'latin1' || enc === 'binary') return 'latin1';
//       if (enc === 'BASE64') return 'base64';
//       if (enc === 'LATIN1' || enc === 'BINARY') return 'latin1';
//       enc = `${enc}`.toLowerCase();
//       if (enc === 'base64') return 'base64';
//       if (enc === 'latin1' || enc === 'binary') return 'latin1';
//       break;
//     case 7:
//       if (
//         enc === 'utf16le' ||
//         enc === 'UTF16LE' ||
//         `${enc}`.toLowerCase() === 'utf16le'
//       )
//         return 'utf16le';
//       break;
//     case 8:
//       if (
//         enc === 'utf-16le' ||
//         enc === 'UTF-16LE' ||
//         `${enc}`.toLowerCase() === 'utf-16le'
//       )
//         return 'utf16le';
//       break;
//     case 9:
//       if (
//         enc === 'base64url' ||
//         enc === 'BASE64URL' ||
//         `${enc}`.toLowerCase() === 'base64url'
//       )
//         return 'base64url';
//       break;
//     default:
//       if (enc === '') return 'utf8';
//   }
// }

// // Return undefined if there is no match.
// // Move the "slow cases" to a separate function to make sure this function gets
// // inlined properly. That prioritizes the common case.
// export function normalizeEncoding(enc?: string) {
//   if (enc == null || enc === 'utf8' || enc === 'utf-8') return 'utf8';
//   return slowCases(enc);
// }

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

export function binaryLikeToArrayBuffer(
  input: BinaryLike,
  encoding: string = 'utf-8'
): ArrayBuffer {
  if (typeof input === 'string') {
    const buffer = Buffer.from(input, encoding);

    return buffer.buffer.slice(
      buffer.byteOffset,
      buffer.byteOffset + buffer.byteLength
    );
  }

  if (isBuffer(input)) {
    return toArrayBuffer(input);
  }

  // TODO add further binary types to BinaryLike, UInt8Array and so for have this array as property
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

export function ab2str(buf: ArrayBuffer, encoding: string = 'hex') {
  console.warn('ROPO ab2str', encoding);

  return Buffer.from(buf).toString(encoding);
}
