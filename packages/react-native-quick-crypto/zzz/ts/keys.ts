import {
  type BinaryLike,
  binaryLikeToArrayBuffer,
  isStringOrBuffer,
  type BufferLike,
  type TypedArray,
} from './utils';
import type { KeyObjectHandle } from './NativeQuickCrypto/webcrypto';
import { NativeQuickCrypto } from './NativeQuickCrypto/NativeQuickCrypto';
import type { KeyPairKey } from './Cipher';

export const kNamedCurveAliases = {
  'P-256': 'prime256v1',
  'P-384': 'secp384r1',
  'P-521': 'secp521r1',
} as const;

export type ImportFormat = 'raw' | 'pkcs8' | 'spki' | 'jwk';

export type KeyPairType = 'rsa' | 'rsa-pss' | 'ec';


export type SecretKeyType = 'hmac' | 'aes';

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
  tagLength?: TagLength;
  additionalData?: BufferLike;
};

export type AesKwParams = {
  name: 'AES-KW';
  wrappingKey?: BufferLike;
};

export type AesKeyGenParams = {
  length: AESLength;
  name?: AESAlgorithm;
};

export type TagLength = 32 | 64 | 96 | 104 | 112 | 120 | 128;

export type AESLength = 128 | 192 | 256;

export type EncryptDecryptParams =
  | AesCbcParams
  | AesCtrParams
  | AesGcmParams
  | RsaOaepParams;




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
  key: BinaryLike | EncodingOptions,
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
    const { key: data, encoding } = key;
    // // The 'key' property can be a KeyObject as well to allow specifying
    // // additional options such as padding along with the key.
    // if (isKeyObject(data)) {
    //   return { data: getKeyObjectHandle(data, ctx) };
    // }
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
export function preparePublicOrPrivateKey(key: BinaryLike | EncodingOptions) {
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

// function getKeyObjectHandle(key: any, ctx: KeyInputContext) {
//   if (ctx === KeyInputContext.kConsumePublic) {
//     throw new Error(
//       'Invalid argument type for "key". Need ArrayBuffer, TypeArray, KeyObject, CryptoKey, string'
//     );
//   }

//   if (key.type !== 'private') {
//     if (
//       ctx === KeyInputContext.kConsumePrivate ||
//       ctx === KeyInputContext.kCreatePublic
//     )
//       throw new Error(`Invalid KeyObject type: ${key.type}, expected 'public'`);
//     if (key.type !== 'public') {
//       throw new Error(
//         `Invalid KeyObject type: ${key.type}, expected 'private' or 'public'`
//       );
//     }
//   }

//   return key.handle;
// }

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

export function createPublicKey(
  key: BinaryLike | EncodingOptions
): PublicKeyObject {
  const { format, type, data, passphrase } = prepareAsymmetricKey(
    key,
    KeyInputContext.kCreatePublic
  );
  const handle = NativeQuickCrypto.webcrypto.createKeyObjectHandle();
  if (format === KFormatType.kKeyFormatJWK) {
    handle.init(KeyType.Public, data);
  } else {
    handle.init(KeyType.Public, data, format, type, passphrase);
  }
  return new PublicKeyObject(handle);
}

export const createPrivateKey = (
  key: BinaryLike | EncodingOptions
): PrivateKeyObject => {
  const { format, type, data, passphrase } = prepareAsymmetricKey(
    key,
    KeyInputContext.kCreatePrivate
  );
  const handle = NativeQuickCrypto.webcrypto.createKeyObjectHandle();
  if (format === KFormatType.kKeyFormatJWK) {
    handle.init(KeyType.Private, data);
  } else {
    handle.init(KeyType.Private, data, format, type, passphrase);
  }
  return new PrivateKeyObject(handle);
};

// const isKeyObject = (obj: any): obj is KeyObject => {
//   return obj != null && obj.keyType !== undefined;
// };



export class SecretKeyObject extends KeyObject {
  constructor(handle: KeyObjectHandle) {
    super('secret', handle);
  }

  // get symmetricKeySize() {
  //   return this[kHandle].getSymmetricKeySize();
  // }

  export(options?: EncodingOptions) {
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
