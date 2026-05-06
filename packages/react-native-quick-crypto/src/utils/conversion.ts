import { Buffer as CraftzdogBuffer } from '@craftzdog/react-native-buffer';
import { Buffer as SafeBuffer } from 'safe-buffer';
import { NitroModules } from 'react-native-nitro-modules';
import type { Utils } from '../specs/utils.nitro';
import type { ABV, BinaryLikeNode, BufferLike } from './types';
import { Platform } from 'react-native';

type UtilsWithStringConverter = Utils & {
  bufferToString(
    buffer: ArrayBuffer,
    encoding: string,
    start?: number,
    end?: number,
  ): string;
  stringToBuffer(str: string, encoding: string): ArrayBuffer;
};

const utils =
  NitroModules.createHybridObject<UtilsWithStringConverter>('Utils');

const isHermes =
  (global as { HermesInternal?: unknown }).HermesInternal != null;

// v0.78.0, https://github.com/facebook/react-native/commit/c6f12254d16d87978383c08065a626d437e60450
// Use jsi::String::getStringData() rather than jsi::String::utf16()
const canGetU16StringFromJsiString = !(
  Platform.constants.reactNativeVersion.major == 0 &&
  Platform.constants.reactNativeVersion.minor < 78
);

// v0.79.0, https://github.com/facebook/react-native/commit/d9d824055e9f24614abd5657f9fc89a6ab3f2da2
const canCreateJsiStringFromUtf16 = !(
  Platform.constants.reactNativeVersion.major == 0 &&
  Platform.constants.reactNativeVersion.minor < 79
);

const baseNativeEncodings = [
  'hex',
  'base64',
  'base64url',
  'utf8',
  'utf-8',
  'latin1',
  'binary',
  'ascii',
];
const nativeStringToBufferEncodings = new Set<string>(baseNativeEncodings);
const nativeBufferToStringEncodings = new Set<string>(baseNativeEncodings);

// The fast and lossless paths for utf16le are only available on Hermes
if (isHermes) {
  if (canGetU16StringFromJsiString) {
    nativeStringToBufferEncodings.add('utf16le');
  }
  if (canCreateJsiStringFromUtf16) {
    nativeBufferToStringEncodings.add('utf16le');
  }
}

// WebCrypto / Web IDL §BufferSource: SharedArrayBuffer-backed inputs must
// be rejected. Concurrent writes from another worker during async crypto
// can corrupt computations or leak intermediate state, so even copying
// the source isn't safe (the copy itself races). Reject at conversion.
// See Node's `lib/internal/webidl.js` BufferSource converter (commit
// bee10872588) — it throws TypeError, matching the WebIDL spec.
//
// We apply this guard to *every* conversion helper, not just the ones
// reached from `subtle.*`. That's deliberately stricter than Node, whose
// classic APIs (`createHash().update`, `createHmac().update`,
// `createCipheriv().update`, etc.) accept SAB-backed views. The TOCTOU
// concern is the same on either side of the WebCrypto / classic line, so
// we prefer the safer default everywhere.
export function rejectSharedArrayBuffer(buf: unknown): void {
  if (typeof SharedArrayBuffer === 'undefined') return;
  if (buf instanceof SharedArrayBuffer) {
    throw new TypeError('SharedArrayBuffer is not a supported BufferSource');
  }
  if (
    ArrayBuffer.isView(buf) &&
    (buf as ArrayBufferView).buffer instanceof SharedArrayBuffer
  ) {
    throw new TypeError(
      'View on a SharedArrayBuffer is not a supported BufferSource',
    );
  }
}

/**
 * Returns the underlying ArrayBuffer of a Buffer / TypedArray view **without
 * copying**, ignoring `byteOffset`/`byteLength`. The full backing storage is
 * exposed.
 *
 * Only use this when the caller separately tracks `byteOffset`/`byteLength`
 * and the native receiver needs to write back into the original memory
 * (e.g. `randomFill`). For data that will be read by native crypto, use
 * `binaryLikeToArrayBuffer`/`toArrayBuffer` instead — those slice to the
 * view's region and won't leak unrelated bytes from the backing buffer.
 */
export const abvToArrayBuffer = (buf: ABV) => {
  rejectSharedArrayBuffer(buf);
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
  rejectSharedArrayBuffer(buf);

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

  throw new TypeError(
    'Input must be a Buffer, ArrayBufferView, or ArrayBuffer.',
  );
}

export function binaryLikeToArrayBuffer(
  input: BinaryLikeNode, // CipherKey adds compat with node types
  encoding: string = 'utf-8',
): ArrayBuffer {
  rejectSharedArrayBuffer(input);

  // string
  if (typeof input === 'string') {
    if (encoding === 'buffer') {
      throw new Error(
        'Cannot create a buffer from a string with a buffer encoding',
      );
    }

    if (nativeStringToBufferEncodings.has(encoding)) {
      return utils.stringToBuffer(input, encoding);
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

  // KeyObject — duck-typed via Symbol.toStringTag to avoid circular dependency
  // with keys/classes. The type assertion must match KeyObjectHandle.exportKey().
  if (
    typeof input === 'object' &&
    input != null &&
    Object.prototype.toString.call(input) === '[object KeyObject]'
  ) {
    return (
      input as { handle: { exportKey(): ArrayBuffer } }
    ).handle.exportKey();
  }

  throw new Error(
    'Invalid argument type for "key". Need ArrayBuffer, TypedArray, KeyObject, CryptoKey, string',
  );
}

export function ab2str(
  buf: ArrayBuffer,
  encoding: string = 'hex',
  start?: number,
  end?: number,
): string {
  if (nativeBufferToStringEncodings.has(encoding)) {
    return bufferToString(buf, encoding, start, end);
  }

  return CraftzdogBuffer.from(buf).toString(encoding, start, end);
}

/** Native C++ buffer-to-string with arguments normalization*/
export function bufferToString(
  buf: ArrayBuffer,
  encoding: string = 'hex',
  start?: number,
  end?: number,
): string {
  // https://github.com/nodejs/node/blob/v24.15.0/lib/buffer.js#L915-L928
  if (start === undefined || start < 0) {
    start = 0;
  } else if (start >= buf.byteLength) {
    return '';
  } else {
    start = Math.trunc(start) || 0;
  }

  if (end === undefined || end > buf.byteLength) {
    end = buf.byteLength;
  } else {
    end = Math.trunc(end) || 0;
  }

  if (end <= start) {
    return '';
  }

  return utils.bufferToString(buf, encoding, start, end);
}

/** Native C++ string-to-buffer — exposed for benchmarking */
export function stringToBuffer(
  str: string,
  encoding: string = 'utf-8',
): ArrayBuffer {
  return utils.stringToBuffer(str, encoding);
}

export const kEmptyObject = Object.freeze(Object.create(null));

export * from './noble';
