import {
  type BinaryLike,
  binaryLikeToArrayBuffer,
  isStringOrBuffer,
  type BufferLike,
  type TypedArray,
} from './Utils';
import type { KeyObjectHandle } from './NativeQuickCrypto/webcrypto';
import { NativeQuickCrypto } from './NativeQuickCrypto/NativeQuickCrypto';
import type { KeyPairKey } from './Cipher';

export const kNamedCurveAliases = {
  'P-256': 'prime256v1',
  'P-384': 'secp384r1',
  'P-521': 'secp521r1',
} as const;

export type NamedCurve = 'P-256' | 'P-384' | 'P-521';

export type ImportFormat = 'raw' | 'pkcs8' | 'spki' | 'jwk';

export type AnyAlgorithm =
  | HashAlgorithm
  | KeyPairAlgorithm
  | SecretKeyAlgorithm
  | SignVerifyAlgorithm
  | DeriveBitsAlgorithm
  | EncryptDecryptAlgorithm
  | 'PBKDF2'
  | 'HKDF';

export type HashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

export type KeyPairType = 'rsa' | 'rsa-pss' | 'ec';

export type RSAKeyPairAlgorithm = 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' | 'RSA-OAEP';
export type ECKeyPairAlgorithm = 'ECDSA' | 'ECDH';
export type CFRGKeyPairAlgorithm = 'Ed25519' | 'Ed448' | 'X25519' | 'X448';
export type AESAlgorithm = 'AES-CTR' | 'AES-CBC' | 'AES-GCM' | 'AES-KW';

export type KeyPairAlgorithm =
  | RSAKeyPairAlgorithm
  | ECKeyPairAlgorithm
  | CFRGKeyPairAlgorithm;

export type SecretKeyAlgorithm = 'HMAC' | AESAlgorithm;

export type SignVerifyAlgorithm =
  | 'RSASSA-PKCS1-v1_5'
  | 'RSA-PSS'
  | 'ECDSA'
  | 'HMAC'
  | 'Ed25519'
  | 'Ed448';

export type DeriveBitsAlgorithm =
  | 'PBKDF2'
  | 'HKDF'
  | 'ECDH'
  | 'X25519'
  | 'X448';

export type RsaOaepParams = {
  name: 'RSA-OAEP';
  label?: BufferLike;
};

export type AesCbcParams = {
  name: 'AES-CBC';
  iv: BufferLike;
};

export type AesCtrParams = {
  name: 'AES-CTR';
  counter: TypedArray;
  length: number;
};

export type AesGcmParams = {
  name: 'AES-GCM';
  iv: BufferLike;
  tagLength: TagLength;
  additionalData: BufferLike;
};

export type AesKwParams = {
  name: 'AES-KW';
  wrappingKey?: BufferLike;
};

export type TagLength = 32 | 64 | 96 | 104 | 112 | 120 | 128;

export type AESLength = 128 | 192 | 256;

export type EncryptDecryptParams =
  | AesCbcParams
  | AesCtrParams
  | AesGcmParams
  | RsaOaepParams;

export type EncryptDecryptAlgorithm =
  | 'RSA-OAEP'
  | 'AES-CTR'
  | 'AES-CBC'
  | 'AES-GCM';

export type SubtleAlgorithm = {
  name: AnyAlgorithm;
  salt?: string;
  iterations?: number;
  hash?: HashAlgorithm;
  namedCurve?: NamedCurve;
  length?: number;
  modulusLength?: number;
  publicExponent?: any;
};

export type KeyUsage =
  | 'encrypt'
  | 'decrypt'
  | 'sign'
  | 'verify'
  | 'deriveKey'
  | 'deriveBits'
  | 'wrapKey'
  | 'unwrapKey';

// On node this value is defined on the native side, for now I'm just creating it here in JS
// TODO(osp) move this into native side to make sure they always match
export enum KFormatType {
  kKeyFormatDER,
  kKeyFormatPEM,
  kKeyFormatJWK,
}

// Same as KFormatType, this enum needs to be defined on the native side
export enum KeyType {
  Secret,
  Public,
  Private,
}

// Same as KFormatType, this enum needs to be defined on the native side
export enum KWebCryptoKeyFormat {
  kWebCryptoKeyFormatRaw,
  kWebCryptoKeyFormatPKCS8,
  kWebCryptoKeyFormatSPKI,
  kWebCryptoKeyFormatJWK,
}

export enum WebCryptoKeyExportStatus {
  OK,
  INVALID_KEY_TYPE,
  FAILED,
}

enum KeyInputContext {
  kConsumePublic,
  kConsumePrivate,
  kCreatePublic,
  kCreatePrivate,
}

export enum KeyEncoding {
  kKeyEncodingPKCS1,
  kKeyEncodingPKCS8,
  kKeyEncodingSPKI,
  kKeyEncodingSEC1,
}

export type EncodingOptions = {
  key: any;
  type?: string;
  encoding?: string;
  format?: string;
  padding?: number;
  cipher?: string;
  passphrase?: string | ArrayBuffer;
};

export type AsymmetricKeyType = 'rsa' | 'rsa-pss' | 'dsa' | 'ec' | undefined;

export type JWK = {
  'kty'?: 'AES' | 'RSA' | 'EC' | 'oct';
  'use'?: 'sig' | 'enc';
  'key_ops'?: KeyUsage[];
  'alg'?: string; // TODO: enumerate these (RFC-7517)
  'crv'?: string;
  'kid'?: string;
  'x5u'?: string;
  'x5c'?: string[];
  'x5t'?: string;
  'x5t#256'?: string;
  'n'?: string;
  'e'?: string;
  'd'?: string;
  'p'?: string;
  'q'?: string;
  'x'?: string;
  'y'?: string;
  'k'?: string;
  'dp'?: string;
  'dq'?: string;
  'qi'?: string;
  'ext'?: boolean;
};

const encodingNames = {
  [KeyEncoding.kKeyEncodingPKCS1]: 'pkcs1',
  [KeyEncoding.kKeyEncodingPKCS8]: 'pkcs8',
  [KeyEncoding.kKeyEncodingSPKI]: 'spki',
  [KeyEncoding.kKeyEncodingSEC1]: 'sec1',
};

export type CryptoKeyPair = {
  publicKey: KeyPairKey;
  privateKey: KeyPairKey;
};

export enum CipherOrWrapMode {
  kWebCryptoCipherEncrypt,
  kWebCryptoCipherDecrypt,
  // kWebCryptoWrapKey,
  // kWebCryptoUnwrapKey,
}

function option(name: string, objName: string | undefined) {
  return objName === undefined
    ? `options.${name}`
    : `options.${objName}.${name}`;
}

function parseKeyFormat(
  formatStr: string | undefined,
  defaultFormat: KFormatType | undefined,
  optionName?: string
) {
  if (formatStr === undefined && defaultFormat !== undefined)
    return defaultFormat;
  else if (formatStr === 'pem') return KFormatType.kKeyFormatPEM;
  else if (formatStr === 'der') return KFormatType.kKeyFormatDER;
  else if (formatStr === 'jwk') return KFormatType.kKeyFormatJWK;
  throw new Error(`Invalid key format str: ${optionName}`);
  // throw new ERR_INVALID_ARG_VALUE(optionName, formatStr);
}

function parseKeyType(
  typeStr: string | undefined,
  required: boolean,
  keyType: string | undefined,
  isPublic: boolean | undefined,
  optionName: string
): KeyEncoding | undefined {
  if (typeStr === undefined && !required) {
    return undefined;
  } else if (typeStr === 'pkcs1') {
    if (keyType !== undefined && keyType !== 'rsa') {
      throw new Error(
        `Crypto incompatible key options: ${typeStr} can only be used for RSA keys`
      );
    }
    return KeyEncoding.kKeyEncodingPKCS1;
  } else if (typeStr === 'spki' && isPublic !== false) {
    return KeyEncoding.kKeyEncodingSPKI;
  } else if (typeStr === 'pkcs8' && isPublic !== true) {
    return KeyEncoding.kKeyEncodingPKCS8;
  } else if (typeStr === 'sec1' && isPublic !== true) {
    if (keyType !== undefined && keyType !== 'ec') {
      throw new Error(
        `Incompatible key options ${typeStr} can only be used for EC keys`
      );
    }
    return KeyEncoding.kKeyEncodingSEC1;
  }

  throw new Error(`Invalid option ${optionName} - ${typeStr}`);
}

function parseKeyFormatAndType(
  enc: EncodingOptions,
  keyType?: string,
  isPublic?: boolean,
  objName?: string
) {
  const { format: formatStr, type: typeStr } = enc;

  const isInput = keyType === undefined;
  const format = parseKeyFormat(
    formatStr,
    isInput ? KFormatType.kKeyFormatPEM : undefined,
    option('format', objName)
  );

  const isRequired =
    (!isInput || format === KFormatType.kKeyFormatDER) &&
    format !== KFormatType.kKeyFormatJWK;

  const type = parseKeyType(
    typeStr,
    isRequired,
    keyType,
    isPublic,
    option('type', objName)
  );
  return { format, type };
}

function parseKeyEncoding(
  enc: EncodingOptions,
  keyType?: string,
  isPublic?: boolean,
  objName?: string
) {
  // validateObject(enc, 'options');

  const isInput = keyType === undefined;

  const { format, type } = parseKeyFormatAndType(
    enc,
    keyType,
    isPublic,
    objName
  );

  let cipher, passphrase, encoding;
  if (isPublic !== true) {
    ({ cipher, passphrase, encoding } = enc);

    if (!isInput) {
      if (cipher != null) {
        if (typeof cipher !== 'string')
          throw new Error(
            `Invalid argument ${option('cipher', objName)}: ${cipher}`
          );
        if (
          format === KFormatType.kKeyFormatDER &&
          (type === KeyEncoding.kKeyEncodingPKCS1 ||
            type === KeyEncoding.kKeyEncodingSEC1)
        ) {
          throw new Error(
            `Incompatible key options ${encodingNames[type]} does not support encryption`
          );
        }
      } else if (passphrase !== undefined) {
        throw new Error(
          `invalid argument ${option('cipher', objName)}: ${cipher}`
        );
      }
    }

    if (
      (isInput && passphrase !== undefined && !isStringOrBuffer(passphrase)) ||
      (!isInput && cipher != null && !isStringOrBuffer(passphrase))
    ) {
      throw new Error(
        `Invalid argument value ${option('passphrase', objName)}: ${passphrase}`
      );
    }
  }

  if (passphrase !== undefined)
    passphrase = binaryLikeToArrayBuffer(passphrase, encoding);

  return { format, type, cipher, passphrase };
}

function prepareAsymmetricKey(
  key:
    | BinaryLike
    | {
        key: any;
        encoding?: string;
        format?: any;
        passphrase?: string | ArrayBuffer;
      },
  ctx: KeyInputContext
): {
  format: KFormatType;
  data: ArrayBuffer;
  type?: KeyEncoding;
  passphrase?: string | ArrayBuffer;
} {
  // TODO(osp) check, KeyObject some node object
  // if (isKeyObject(key)) {
  //   // Best case: A key object, as simple as that.
  //   return { data: getKeyObjectHandle(key, ctx) };
  // } else
  // if (isCryptoKey(key)) {
  //   return { data: getKeyObjectHandle(key[kKeyObject], ctx) };
  // } else
  if (isStringOrBuffer(key)) {
    // Expect PEM by default, mostly for backward compatibility.
    return {
      format: KFormatType.kKeyFormatPEM,
      data: binaryLikeToArrayBuffer(key),
    };
  } else if (typeof key === 'object') {
    const {
      key: data,
      encoding,
      // format
    } = key;
    // // The 'key' property can be a KeyObject as well to allow specifying
    // // additional options such as padding along with the key.
    // if (isKeyObject(data)) return { data: getKeyObjectHandle(data, ctx) };
    // else if (isCryptoKey(data))
    //   return { data: getKeyObjectHandle(data[kKeyObject], ctx) };
    // else if (isJwk(data) && format === 'jwk')
    //   return { data: getKeyObjectHandleFromJwk(data, ctx), format: 'jwk' };
    // Either PEM or DER using PKCS#1 or SPKI.
    if (!isStringOrBuffer(data)) {
      throw new Error(
        'prepareAsymmetricKey: key is not a string or ArrayBuffer'
      );
    }

    const isPublic =
      ctx === KeyInputContext.kConsumePrivate ||
      ctx === KeyInputContext.kCreatePrivate
        ? false
        : undefined;

    return {
      data: binaryLikeToArrayBuffer(data, encoding),
      ...parseKeyEncoding(key, undefined, isPublic),
    };
  }

  throw new Error('[prepareAsymetricKey] Invalid argument key: ${key}');
}

// TODO(osp) any here is a node KeyObject
export function preparePrivateKey(key: BinaryLike | EncodingOptions) {
  return prepareAsymmetricKey(key, KeyInputContext.kConsumePrivate);
}

// TODO(osp) any here is a node KeyObject
export function preparePublicOrPrivateKey(
  key:
    | BinaryLike
    | { key: any; encoding?: string; format?: any; padding?: number }
) {
  return prepareAsymmetricKey(key, KeyInputContext.kConsumePublic);
}

// Parses the public key encoding based on an object. keyType must be undefined
// when this is used to parse an input encoding and must be a valid key type if
// used to parse an output encoding.
export function parsePublicKeyEncoding(
  enc: EncodingOptions,
  keyType: string | undefined,
  objName?: string
) {
  return parseKeyEncoding(enc, keyType, keyType ? true : undefined, objName);
}

// Parses the private key encoding based on an object. keyType must be undefined
// when this is used to parse an input encoding and must be a valid key type if
// used to parse an output encoding.
export function parsePrivateKeyEncoding(
  enc: EncodingOptions,
  keyType: string | undefined,
  objName?: string
) {
  return parseKeyEncoding(enc, keyType, false, objName);
}

function prepareSecretKey(
  key: BinaryLike,
  encoding?: string,
  bufferOnly = false
): any {
  try {
    if (!bufferOnly) {
      // TODO: maybe use `key.constructor.name === 'KeyObject'` ?
      if (key instanceof KeyObject) {
        if (key.type !== 'secret')
          throw new Error(
            `invalid KeyObject type: ${key.type}, expected 'secret'`
          );
        return key.handle;
      }
      // TODO: maybe use `key.constructor.name === 'CryptoKey'` ?
      else if (key instanceof CryptoKey) {
        if (key.type !== 'secret')
          throw new Error(
            `invalid CryptoKey type: ${key.type}, expected 'secret'`
          );
        return key.keyObject.handle;
      }
    }

    if (key instanceof ArrayBuffer) {
      return key;
    }

    return binaryLikeToArrayBuffer(key, encoding);
  } catch (error) {
    throw new Error(
      'Invalid argument type for "key". Need ArrayBuffer, TypedArray, KeyObject, CryptoKey, string',
      { cause: error }
    );
  }
}

export function createSecretKey(key: any, encoding?: string) {
  const k = prepareSecretKey(key, encoding, true);
  const handle = NativeQuickCrypto.webcrypto.createKeyObjectHandle();
  handle.init(KeyType.Secret, k);
  return new SecretKeyObject(handle);
}

export class CryptoKey {
  keyObject: KeyObject;
  keyAlgorithm: SubtleAlgorithm;
  keyUsages: KeyUsage[];
  keyExtractable: boolean;

  constructor(
    keyObject: KeyObject,
    keyAlgorithm: SubtleAlgorithm,
    keyUsages: KeyUsage[],
    keyExtractable: boolean
  ) {
    this.keyObject = keyObject;
    this.keyAlgorithm = keyAlgorithm;
    this.keyUsages = keyUsages;
    this.keyExtractable = keyExtractable;
  }

  inspect(_depth: number, _options: any): any {
    throw new Error('CryptoKey.inspect is not implemented');
    // if (depth < 0) return this;

    // const opts = {
    //   ...options,
    //   depth: options.depth == null ? null : options.depth - 1,
    // };

    // return `CryptoKey ${inspect(
    //   {
    //     type: this.type,
    //     extractable: this.extractable,
    //     algorithm: this.algorithm,
    //     usages: this.usages,
    //   },
    //   opts
    // )}`;
  }

  get type() {
    // if (!(this instanceof CryptoKey)) throw new Error('Invalid CryptoKey');
    return this.keyObject.type;
  }

  get extractable() {
    return this.keyExtractable;
  }

  get algorithm() {
    return this.keyAlgorithm;
  }

  get usages() {
    return this.keyUsages;
  }
}

class KeyObject {
  handle: KeyObjectHandle;
  type: 'public' | 'secret' | 'private' | 'unknown' = 'unknown';
  export(_options?: EncodingOptions): ArrayBuffer {
    return new ArrayBuffer(0);
  }

  constructor(type: string, handle: KeyObjectHandle) {
    if (type !== 'secret' && type !== 'public' && type !== 'private')
      throw new Error(`invalid KeyObject type: ${type}`);
    this.handle = handle;
    this.type = type;
  }

  // get type(): string {
  //   return this.type;
  // }

  // static from(key) {
  //   if (!isCryptoKey(key))
  //     throw new ERR_INVALID_ARG_TYPE('key', 'CryptoKey', key);
  //   return key[kKeyObject];
  // }

  // equals(otherKeyObject) {
  //   if (!isKeyObject(otherKeyObject)) {
  //     throw new ERR_INVALID_ARG_TYPE(
  //       'otherKeyObject',
  //       'KeyObject',
  //       otherKeyObject
  //     );
  //   }

  //   return (
  //     otherKeyObject.type === this.type &&
  //     this[kHandle].equals(otherKeyObject[kHandle])
  //   );
  // }
}

export class SecretKeyObject extends KeyObject {
  constructor(handle: KeyObjectHandle) {
    super('secret', handle);
  }

  // get symmetricKeySize() {
  //   return this[kHandle].getSymmetricKeySize();
  // }

  export(options: EncodingOptions) {
    if (options !== undefined) {
      if (options.format === 'jwk') {
        throw new Error('SecretKey export for jwk is not implemented');
        // return this.handle.exportJwk({}, false);
      }
    }
    return this.handle.export();
  }
}

// const kAsymmetricKeyType = Symbol('kAsymmetricKeyType');
// const kAsymmetricKeyDetails = Symbol('kAsymmetricKeyDetails');

// function normalizeKeyDetails(details = {}) {
//   if (details.publicExponent !== undefined) {
//     return {
//       ...details,
//       publicExponent: bigIntArrayToUnsignedBigInt(
//         new Uint8Array(details.publicExponent)
//       ),
//     };
//   }
//   return details;
// }

class AsymmetricKeyObject extends KeyObject {
  constructor(type: string, handle: KeyObjectHandle) {
    super(type, handle);
  }

  private _asymmetricKeyType?: AsymmetricKeyType;

  get asymmetricKeyType(): AsymmetricKeyType {
    if (!this._asymmetricKeyType) {
      this._asymmetricKeyType = this.handle.getAsymmetricKeyType();
    }
    return this._asymmetricKeyType;
  }

  // get asymmetricKeyDetails() {
  //   switch (this._asymmetricKeyType) {
  //     case 'rsa':
  //     case 'rsa-pss':
  //     case 'dsa':
  //     case 'ec':
  //       return (
  //         this[kAsymmetricKeyDetails] ||
  //         (this[kAsymmetricKeyDetails] = normalizeKeyDetails(
  //           this[kHandle].keyDetail({})
  //         ))
  //       );
  //     default:
  //       return {};
  //   }
  // }
}

export class PublicKeyObject extends AsymmetricKeyObject {
  constructor(handle: KeyObjectHandle) {
    super('public', handle);
  }

  export(options: EncodingOptions) {
    if (options?.format === 'jwk') {
      throw new Error('PublicKey export for jwk is not implemented');
      // return this.handle.exportJwk({}, false);
    }
    const { format, type } = parsePublicKeyEncoding(
      options,
      this.asymmetricKeyType
    );
    return this.handle.export(format, type);
  }
}

export class PrivateKeyObject extends AsymmetricKeyObject {
  constructor(handle: KeyObjectHandle) {
    super('private', handle);
  }

  export(options: EncodingOptions) {
    if (options?.format === 'jwk') {
      if (options.passphrase !== undefined) {
        throw new Error('jwk does not support encryption');
      }
      throw new Error('PrivateKey export for jwk is not implemented');
      // return this.handle.exportJwk({}, false);
    }
    const { format, type, cipher, passphrase } = parsePrivateKeyEncoding(
      options,
      this.asymmetricKeyType
    );
    return this.handle.export(format, type, cipher, passphrase);
  }
}

export const isCryptoKey = (obj: any): boolean => {
  return obj !== null && obj?.keyObject !== undefined;
};
