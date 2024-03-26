import { Buffer } from '@craftzdog/react-native-buffer';
import type {
  AnyAlgorithm,
  DeriveBitsAlgorithm,
  EncryptDecryptAlgorithm,
  HashAlgorithm,
  KeyPairAlgorithm,
  SecretKeyAlgorithm,
  SignVerifyAlgorithm,
  SubtleAlgorithm,
} from './keys';

export type BufferLike = ArrayBuffer | Buffer | ArrayBufferView;
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

type DOMName =
  | string
  | {
      name: string;
      cause: any;
    };

// Mimics node behavior for default global encoding
let defaultEncoding: CipherEncoding = 'buffer';

export function setDefaultEncoding(encoding: CipherEncoding) {
  defaultEncoding = encoding;
}

export function getDefaultEncoding(): CipherEncoding {
  return defaultEncoding;
}

export const kEmptyObject = Object.freeze(Object.create(null));

// Should be used by Cipher (or any other module that requires valid encodings)
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

export function toArrayBuffer(buf: Buffer): ArrayBuffer {
  if (buf?.buffer?.slice) {
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }
  const ab = new ArrayBuffer(buf.length);
  const view = new Uint8Array(ab);
  for (let i = 0; i < buf.length; ++i) {
    view[i] = buf[i]!;
  }
  return ab;
}

export function bufferLikeToArrayBuffer(buf: BufferLike): ArrayBuffer {
  return Buffer.isBuffer(buf)
    ? buf.buffer
    : ArrayBuffer.isView(buf)
    ? buf.buffer
    : buf;
}

export function binaryLikeToArrayBuffer(
  input: BinaryLike,
  encoding: string = 'utf-8'
): ArrayBuffer {
  if (typeof input === 'string') {
    if (encoding === 'buffer') {
      throw new Error(
        'Cannot create a buffer from a string with a buffer encoding'
      );
    }

    const buffer = Buffer.from(input, encoding);

    return buffer.buffer.slice(
      buffer.byteOffset,
      buffer.byteOffset + buffer.byteLength
    );
  }

  if (Buffer.isBuffer(input)) {
    return toArrayBuffer(input);
  }

  // TODO add further binary types to BinaryLike, UInt8Array and so for have this array as property
  if (ArrayBuffer.isView(input)) {
    return input.buffer;
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
  return Buffer.from(buf).toString(encoding);
}

export function validateString(str: any, name?: string): str is string {
  const isString = typeof str === 'string';
  if (!isString) {
    throw new Error(`${name} is not a string`);
  }
  return isString;
}

export function validateFunction(f: any): f is Function {
  return f != null && typeof f === 'function';
}

export function isStringOrBuffer(val: any): val is string | ArrayBuffer {
  return typeof val === 'string' || ArrayBuffer.isView(val);
}

export function validateObject<T>(
  value: any,
  name: string,
  options?: {
    allowArray: boolean;
    allowFunction: boolean;
    nullable: boolean;
  } | null
): value is T {
  const useDefaultOptions = options == null;
  const allowArray = useDefaultOptions ? false : options.allowArray;
  const allowFunction = useDefaultOptions ? false : options.allowFunction;
  const nullable = useDefaultOptions ? false : options.nullable;
  if (
    (!nullable && value === null) ||
    (!allowArray && Array.isArray(value)) ||
    (typeof value !== 'object' &&
      (!allowFunction || typeof value !== 'function'))
  ) {
    throw new Error(`${name} is not a valid object $${value}`);
  }
  return true;
}

export function validateInt32(
  value: any,
  name: string,
  min = -2147483648,
  max = 2147483647
) {
  // The defaults for min and max correspond to the limits of 32-bit integers.
  if (typeof value !== 'number') {
    throw new Error(`Invalid argument - ${name} is not a number: ${value}`);
  }
  if (!Number.isInteger(value)) {
    throw new Error(
      `Argument out of range - ${name} out of integer range: ${value}`
    );
  }
  if (value < min || value > max) {
    throw new Error(
      `Invalid argument - ${name} out of range >= ${min} && <= ${max}: ${value}`
    );
  }
}

export function validateUint32(
  value: number,
  name: string,
  positive?: boolean
) {
  if (typeof value !== 'number') {
    // throw new ERR_INVALID_ARG_TYPE(name, 'number', value);
    throw new Error(`Invalid argument - ${name} is not a number: ${value}`);
  }
  if (!Number.isInteger(value)) {
    // throw new ERR_OUT_OF_RANGE(name, 'an integer', value);
    throw new Error(
      `Argument out of range - ${name} out of integer range: ${value}`
    );
  }
  const min = positive ? 1 : 0;
  // 2 ** 32 === 4294967296
  const max = 4294967295;
  if (value < min || value > max) {
    // throw new ERR_OUT_OF_RANGE(name, `>= ${min} && <= ${max}`, value);
    throw new Error(
      `Invalid argument - ${name} out of range >= ${min} && <= ${max}: ${value}`
    );
  }
}

export function hasAnyNotIn(set: string[], checks: string[]) {
  for (const s of set) {
    if (!checks.includes(s)) {
      return true;
    }
  }
  return false;
}

export function lazyDOMException(message: string, domName: DOMName): Error {
  let cause = '';
  if (typeof domName !== 'string') {
    cause = `\nCaused by: ${domName.cause}`;
  }

  return new Error(`[${domName}]: ${message}${cause}`);
}

// from lib/internal/crypto/util.js

// The maximum buffer size that we'll support in the WebCrypto impl
const kMaxBufferLength = 2 ** 31 - 1;

// // The EC named curves that we currently support via the Web Crypto API.
// const kNamedCurveAliases = {
//   'P-256': 'prime256v1',
//   'P-384': 'secp384r1',
//   'P-521': 'secp521r1',
// };

// const kAesKeyLengths = [128, 192, 256];

// // These are the only hash algorithms we currently support via
// // the Web Crypto API.
// const kHashTypes = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];

type SupportedAlgorithm<Type extends string> = {
  [key in Type]: string | null;
};

type SupportedAlgorithms = {
  'digest': SupportedAlgorithm<HashAlgorithm>;
  'generateKey': SupportedAlgorithm<KeyPairAlgorithm | SecretKeyAlgorithm>;
  'sign': SupportedAlgorithm<SignVerifyAlgorithm>;
  'verify': SupportedAlgorithm<SignVerifyAlgorithm>;
  'importKey': SupportedAlgorithm<
    KeyPairAlgorithm | 'PBKDF2' | SecretKeyAlgorithm | 'HKDF'
  >;
  'deriveBits': SupportedAlgorithm<DeriveBitsAlgorithm>;
  'encrypt': SupportedAlgorithm<EncryptDecryptAlgorithm>;
  'decrypt': SupportedAlgorithm<EncryptDecryptAlgorithm>;
  'get key length': SupportedAlgorithm<SecretKeyAlgorithm | 'PBKDF2' | 'HKDF'>;
  'wrapKey': SupportedAlgorithm<'AES-KW'>;
  'unwrapKey': SupportedAlgorithm<'AES-KW'>;
};

export type Operation =
  | 'digest'
  | 'generateKey'
  | 'sign'
  | 'verify'
  | 'importKey'
  | 'deriveBits'
  | 'encrypt'
  | 'decrypt'
  | 'get key length'
  | 'wrapKey'
  | 'unwrapKey';

const kSupportedAlgorithms: SupportedAlgorithms = {
  'digest': {
    'SHA-1': null,
    'SHA-256': null,
    'SHA-384': null,
    'SHA-512': null,
  },
  'generateKey': {
    'RSASSA-PKCS1-v1_5': 'RsaHashedKeyGenParams',
    'RSA-PSS': 'RsaHashedKeyGenParams',
    'RSA-OAEP': 'RsaHashedKeyGenParams',
    'ECDSA': 'EcKeyGenParams',
    'ECDH': 'EcKeyGenParams',
    'AES-CTR': 'AesKeyGenParams',
    'AES-CBC': 'AesKeyGenParams',
    'AES-GCM': 'AesKeyGenParams',
    'AES-KW': 'AesKeyGenParams',
    'HMAC': 'HmacKeyGenParams',
    'X25519': null,
    'Ed25519': null,
    'X448': null,
    'Ed448': null,
  },
  'sign': {
    'RSASSA-PKCS1-v1_5': null,
    'RSA-PSS': 'RsaPssParams',
    'ECDSA': 'EcdsaParams',
    'HMAC': null,
    'Ed25519': null,
    'Ed448': 'Ed448Params',
  },
  'verify': {
    'RSASSA-PKCS1-v1_5': null,
    'RSA-PSS': 'RsaPssParams',
    'ECDSA': 'EcdsaParams',
    'HMAC': null,
    'Ed25519': null,
    'Ed448': 'Ed448Params',
  },
  'importKey': {
    'RSASSA-PKCS1-v1_5': 'RsaHashedImportParams',
    'RSA-PSS': 'RsaHashedImportParams',
    'RSA-OAEP': 'RsaHashedImportParams',
    'ECDSA': 'EcKeyImportParams',
    'ECDH': 'EcKeyImportParams',
    'HMAC': 'HmacImportParams',
    'HKDF': null,
    'PBKDF2': null,
    'AES-CTR': null,
    'AES-CBC': null,
    'AES-GCM': null,
    'AES-KW': null,
    'Ed25519': null,
    'X25519': null,
    'Ed448': null,
    'X448': null,
  },
  'deriveBits': {
    HKDF: 'HkdfParams',
    PBKDF2: 'Pbkdf2Params',
    ECDH: 'EcdhKeyDeriveParams',
    X25519: 'EcdhKeyDeriveParams',
    X448: 'EcdhKeyDeriveParams',
  },
  'encrypt': {
    'RSA-OAEP': 'RsaOaepParams',
    'AES-CBC': 'AesCbcParams',
    'AES-GCM': 'AesGcmParams',
    'AES-CTR': 'AesCtrParams',
  },
  'decrypt': {
    'RSA-OAEP': 'RsaOaepParams',
    'AES-CBC': 'AesCbcParams',
    'AES-GCM': 'AesGcmParams',
    'AES-CTR': 'AesCtrParams',
  },
  'get key length': {
    'AES-CBC': 'AesDerivedKeyParams',
    'AES-CTR': 'AesDerivedKeyParams',
    'AES-GCM': 'AesDerivedKeyParams',
    'AES-KW': 'AesDerivedKeyParams',
    'HMAC': 'HmacImportParams',
    'HKDF': null,
    'PBKDF2': null,
  },
  'wrapKey': {
    'AES-KW': null,
  },
  'unwrapKey': {
    'AES-KW': null,
  },
};

// const simpleAlgorithmDictionaries = {
//   AesGcmParams: { iv: 'BufferSource', additionalData: 'BufferSource' },
//   RsaHashedKeyGenParams: { hash: 'HashAlgorithmIdentifier' },
//   EcKeyGenParams: {},
//   HmacKeyGenParams: { hash: 'HashAlgorithmIdentifier' },
//   RsaPssParams: {},
//   EcdsaParams: { hash: 'HashAlgorithmIdentifier' },
//   HmacImportParams: { hash: 'HashAlgorithmIdentifier' },
//   HkdfParams: {
//     hash: 'HashAlgorithmIdentifier',
//     salt: 'BufferSource',
//     info: 'BufferSource',
//   },
//   Ed448Params: { context: 'BufferSource' },
//   Pbkdf2Params: { hash: 'HashAlgorithmIdentifier', salt: 'BufferSource' },
//   RsaOaepParams: { label: 'BufferSource' },
//   RsaHashedImportParams: { hash: 'HashAlgorithmIdentifier' },
//   EcKeyImportParams: {},
// };

export const validateMaxBufferLength = (
  data: BinaryLike | BufferLike,
  name: string
): void => {
  const length = typeof data === 'string' ? data.length : data.byteLength;
  if (length > kMaxBufferLength) {
    throw lazyDOMException(
      `${name} must be less than ${kMaxBufferLength + 1} bits`,
      'OperationError'
    );
  }
};

// https://w3c.github.io/webcrypto/#algorithm-normalization-normalize-an-algorithm
// adapted for Node.js from Deno's implementation
// https://github.com/denoland/deno/blob/v1.29.1/ext/crypto/00_crypto.js#L195
export const normalizeAlgorithm = (
  algorithm: SubtleAlgorithm | AnyAlgorithm,
  op: Operation
): SubtleAlgorithm => {
  if (typeof algorithm === 'string')
    return normalizeAlgorithm({ name: algorithm }, op);

  // 1.
  const registeredAlgorithms = kSupportedAlgorithms[op];
  // 2. 3.
  // commented, because typescript takes care of this for us 🤞👀
  // const initialAlg = webidl.converters.Algorithm(algorithm, {
  //   prefix: 'Failed to normalize algorithm',
  //   context: 'passed algorithm',
  // });

  // 4.
  let algName = algorithm.name;

  // 5.
  let desiredType: string | null | undefined;
  for (const key in registeredAlgorithms) {
    if (!registeredAlgorithms.hasOwnProperty(key)) {
      continue;
    }
    if (key.toUpperCase() === algName.toUpperCase()) {
      algName = key as AnyAlgorithm;
      // @ts-ignore
      desiredType = registeredAlgorithms[algName];
    }
  }
  if (desiredType === undefined)
    throw lazyDOMException('Unrecognized algorithm name', 'NotSupportedError');

  // Fast path everything below if the registered dictionary is null
  if (desiredType === null) return { name: algName };

  throw lazyDOMException(
    `normalizeAlgorithm() not implemented for ${op} / ${algName} / ${desiredType}`,
    'NotSupportedError'
  );
  // TODO: implement these below when needed

  // // 8.
  // const normalizedAlgorithm = webidl.converters[desiredType](algorithm, {
  //   prefix: 'Failed to normalize algorithm',
  //   context: 'passed algorithm',
  // });
  // // 9.
  // normalizedAlgorithm.name = algName;

  // // 9.
  // const dict = simpleAlgorithmDictionaries[desiredType];
  // // 10.
  // const dictKeys = dict ? Object.keys(dict) : [];
  // for (let i = 0; i < dictKeys.length; i++) {
  //   const member = dictKeys[i];
  //   if (!dict.hasOwnProperty(member)) continue;
  //   const idlType = dict[member];
  //   const idlValue = normalizedAlgorithm[member];
  //   // 3.
  //   if (idlType === 'BufferSource' && idlValue) {
  //     const isView = ArrayBufferIsView(idlValue);
  //     normalizedAlgorithm[member] = TypedArrayPrototypeSlice(
  //       new Uint8Array(
  //         isView ? getDataViewOrTypedArrayBuffer(idlValue) : idlValue,
  //         isView ? getDataViewOrTypedArrayByteOffset(idlValue) : 0,
  //         isView
  //           ? getDataViewOrTypedArrayByteLength(idlValue)
  //           : ArrayBufferPrototypeGetByteLength(idlValue)
  //       )
  //     );
  //   } else if (idlType === 'HashAlgorithmIdentifier') {
  //     normalizedAlgorithm[member] = normalizeAlgorithm(idlValue, 'digest');
  //   } else if (idlType === 'AlgorithmIdentifier') {
  //     // This extension point is not used by any supported algorithm (yet?)
  //     throw lazyDOMException('Not implemented.', 'NotSupportedError');
  //   }
  // }

  // return normalizedAlgorithm;
};

export * from './Hashnames';
