import {
  type BinaryLike,
  binaryLikeToArrayBuffer,
  isStringOrBuffer,
} from './Utils';
import type { KeyObjectHandle } from './NativeQuickCrypto/webcrypto';

export const kNamedCurveAliases = {
  'P-256': 'prime256v1',
  'P-384': 'secp384r1',
  'P-521': 'secp521r1',
} as const;

export type NamedCurve = 'P-256' | 'P-384' | 'P-521';

export type ImportFormat = 'raw' | 'pkcs8' | 'spki' | 'jwk';
export type SubtleAlgorithm = {
  name: 'ECDSA' | 'ECDH';
  namedCurve: NamedCurve;
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
enum KFormatType {
  kKeyFormatDER,
  kKeyFormatPEM,
  kKeyFormatJWK,
}

// Same as KFormatType, this enum needs to be defined on the native side
export enum KWebCryptoKeyFormat {
  kWebCryptoKeyFormatRaw,
  kWebCryptoKeyFormatPKCS8,
  kWebCryptoKeyFormatSPKI,
  kWebCryptoKeyFormatJWK,
}

enum KeyInputContext {
  kConsumePublic,
  kConsumePrivate,
  kCreatePublic,
  kCreatePrivate,
}

enum KeyEncoding {
  kKeyEncodingPKCS1,
  kKeyEncodingPKCS8,
  kKeyEncodingSPKI,
  kKeyEncodingSEC1,
}

const encodingNames = {
  [KeyEncoding.kKeyEncodingPKCS1]: 'pkcs1',
  [KeyEncoding.kKeyEncodingPKCS8]: 'pkcs8',
  [KeyEncoding.kKeyEncodingSPKI]: 'spki',
  [KeyEncoding.kKeyEncodingSEC1]: 'sec1',
};

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
) {
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
  enc: {
    key: any;
    type?: string;
    encoding?: string;
    format?: string;
    cipher?: string;
    passphrase?: string;
  },
  keyType: string | undefined,
  isPublic: boolean | undefined,
  objName: string | undefined
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
  enc: {
    key: any;
    type?: string;
    encoding?: string;
    format?: string;
    cipher?: string;
    passphrase?: string;
  },
  keyType: string | undefined,
  isPublic: boolean | undefined,
  objName?: string | undefined
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
    | { key: any; encoding?: string; format?: any; passphrase?: string },
  ctx: KeyInputContext
): {
  format: KFormatType;
  data: ArrayBuffer;
  type?: any;
  passphrase?: any;
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
export function preparePrivateKey(
  key:
    | BinaryLike
    | {
        key: any;
        encoding?: string;
        format?: any;
        padding?: number;
        passphrase?: string;
      }
) {
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
  enc: {
    key: any;
    encoding?: string;
    format?: string;
    cipher?: string;
    passphrase?: string;
  },
  keyType: string | undefined,
  objName?: string
) {
  return parseKeyEncoding(enc, keyType, keyType ? true : undefined, objName);
}

// Parses the private key encoding based on an object. keyType must be undefined
// when this is used to parse an input encoding and must be a valid key type if
// used to parse an output encoding.
export function parsePrivateKeyEncoding(
  enc: {
    key: any;
    encoding?: string;
    format?: string;
    cipher?: string;
    passphrase?: string;
  },
  keyType: string | undefined,
  objName?: string
) {
  return parseKeyEncoding(enc, keyType, false, objName);
}

export class CryptoKey {
  keyObject: PublicKeyObject;
  algorithm: SubtleAlgorithm;
  keyUsages: KeyUsage[];
  extractable: boolean;

  constructor(
    keyObject: KeyObject,
    algorithm: SubtleAlgorithm,
    keyUsages: KeyUsage[],
    extractable: boolean
  ) {
    this.keyObject = keyObject;
    this.algorithm = algorithm;
    this.keyUsages = keyUsages;
    this.extractable = extractable;
  }

  inspect(_depth: number, _options: any): any {
    throw new Error('NOT IMPLEMENTED');
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

  // get extractable() {
  //   if (!(this instanceof CryptoKey)) throw new ERR_INVALID_THIS('CryptoKey');
  //   return this[kExtractable];
  // }

  // get algorithm() {
  //   if (!(this instanceof CryptoKey)) throw new ERR_INVALID_THIS('CryptoKey');
  //   return this[kAlgorithm];
  // }

  // get usages() {
  //   if (!(this instanceof CryptoKey)) throw new ERR_INVALID_THIS('CryptoKey');
  //   return ArrayFrom(this[kKeyUsages]);
  // }
}

// ObjectDefineProperties(CryptoKey.prototype, {
//   type: kEnumerableProperty,
//   extractable: kEnumerableProperty,
//   algorithm: kEnumerableProperty,
//   usages: kEnumerableProperty,
//   [SymbolToStringTag]: {
//     __proto__: null,
//     configurable: true,
//     value: 'CryptoKey',
//   },
// });

class KeyObject {
  handle: KeyObjectHandle;
  type: 'public' | 'secret' | 'private' | 'unknown' = 'unknown';

  constructor(type: string, handle: KeyObjectHandle) {
    if (type !== 'secret' && type !== 'public' && type !== 'private')
      throw new Error(`type: ${type}`);
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

// ObjectDefineProperties(KeyObject.prototype, {
//   [SymbolToStringTag]: {
//     __proto__: null,
//     configurable: true,
//     value: 'KeyObject',
//   },
// });

export class SecretKeyObject extends KeyObject {
  constructor(handle: KeyObjectHandle) {
    super('secret', handle);
  }

  // get symmetricKeySize() {
  //   return this[kHandle].getSymmetricKeySize();
  // }

  // export(options) {
  //   if (options !== undefined) {
  //     validateObject(options, 'options');
  //     validateOneOf(options.format, 'options.format', [
  //       undefined,
  //       'buffer',
  //       'jwk',
  //     ]);
  //     if (options.format === 'jwk') {
  //       return this[kHandle].exportJwk({}, false);
  //     }
  //   }
  //   return this[kHandle].export();
  // }
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

  // get asymmetricKeyType() {
  //   return (
  //     this[kAsymmetricKeyType] ||
  //     (this[kAsymmetricKeyType] = this[kHandle].getAsymmetricKeyType())
  //   );
  // }

  // get asymmetricKeyDetails() {
  //   switch (this.asymmetricKeyType) {
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

  // export(options: any) {
  //   if (options && options.format === 'jwk') {
  //     return this[kHandle].exportJwk({}, false);
  //   }
  //   const { format, type } = parsePublicKeyEncoding(
  //     options,
  //     this.asymmetricKeyType
  //   );
  //   return this[kHandle].export(format, type);
  // }
}

export class PrivateKeyObject extends AsymmetricKeyObject {
  constructor(handle: KeyObjectHandle) {
    super('private', handle);
  }

  // export(options) {
  //   if (options && options.format === 'jwk') {
  //     if (options.passphrase !== undefined) {
  //       throw new ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS(
  //         'jwk',
  //         'does not support encryption'
  //       );
  //     }
  //     return this[kHandle].exportJwk({}, false);
  //   }
  //   const { format, type, cipher, passphrase } = parsePrivateKeyEncoding(
  //     options,
  //     this.asymmetricKeyType
  //   );
  //   return this[kHandle].export(format, type, cipher, passphrase);
  // }
}
