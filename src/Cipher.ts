import { NativeQuickCrypto } from './NativeQuickCrypto/NativeQuickCrypto';
import Stream, { type TransformOptions } from 'readable-stream';
import {
  type BinaryLike,
  binaryLikeToArrayBuffer,
  type CipherEncoding,
  type Encoding,
  getDefaultEncoding,
  kEmptyObject,
  validateFunction,
  validateObject,
  validateString,
  validateUint32,
  validateInt32,
  type BinaryLikeNode,
  type CipherType,
} from './Utils';
import { type InternalCipher, KeyVariant } from './NativeQuickCrypto/Cipher';
import type {
  CipherCCMOptions,
  CipherCCMTypes,
  CipherGCMTypes,
  CipherGCMOptions,
  CipherOCBOptions,
  CipherOCBTypes,
  DecipherGCM,
  DecipherOCB,
  DecipherCCM,
  CipherCCM,
  CipherOCB,
  CipherGCM,
} from 'crypto'; // @types/node
import { StringDecoder } from 'string_decoder';
import { Buffer } from '@craftzdog/react-native-buffer';
import { Buffer as SBuffer } from 'safe-buffer';
import { constants } from './constants';
import {
  CryptoKey,
  KeyEncoding,
  KFormatType,
  parsePrivateKeyEncoding,
  parsePublicKeyEncoding,
  preparePrivateKey,
  preparePublicOrPrivateKey,
  type CryptoKeyPair,
  type EncodingOptions,
  type KeyPairType,
  type NamedCurve,
} from './keys';
import type { KeyObjectHandle } from './NativeQuickCrypto/webcrypto';

export enum ECCurve {
  OPENSSL_EC_EXPLICIT_CURVE,
  OPENSSL_EC_NAMED_CURVE,
}

// make sure that nextTick is there
global.process.nextTick = setImmediate;

const createInternalCipher = NativeQuickCrypto.createCipher;
const createInternalDecipher = NativeQuickCrypto.createDecipher;
const _publicEncrypt = NativeQuickCrypto.publicEncrypt;
const _publicDecrypt = NativeQuickCrypto.publicDecrypt;
const _privateDecrypt = NativeQuickCrypto.privateDecrypt;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function getUIntOption(options: Record<string, any>, key: string) {
  let value;
  if (options && (value = options[key]) != null) {
    // >>> Turns any type into a positive integer (also sets the sign bit to 0)
    if (value >>> 0 !== value) throw new Error(`options.${key}: ${value}`);
    return value;
  }
  return -1;
}

function normalizeEncoding(enc: string) {
  if (!enc) return 'utf8';
  let retried;
  while (true) {
    switch (enc) {
      case 'utf8':
      case 'utf-8':
        return 'utf8';
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return 'utf16le';
      case 'latin1':
      case 'binary':
        return 'latin1';
      case 'base64':
      case 'ascii':
      case 'hex':
        return enc;
      default:
        if (retried) return; // undefined
        enc = ('' + enc).toLowerCase();
        retried = true;
    }
  }
}

function validateEncoding(data: string, encoding: string) {
  const normalizedEncoding = normalizeEncoding(encoding);
  const length = data.length;

  if (normalizedEncoding === 'hex' && length % 2 !== 0) {
    throw new Error(`Encoding ${encoding} not valid for data length ${length}`);
  }
}

function getDecoder(decoder?: StringDecoder, encoding?: BufferEncoding) {
  return decoder ?? new StringDecoder(encoding);
}

class CipherCommon extends Stream.Transform {
  private internal: InternalCipher;
  private decoder: StringDecoder | undefined;

  constructor(
    cipherType: string,
    cipherKey: BinaryLikeNode,
    isCipher: boolean,
    options: Record<string, TransformOptions> = {},
    iv?: BinaryLike | null,
  ) {
    super(options);
    const cipherKeyBuffer = binaryLikeToArrayBuffer(cipherKey);
    // defaults to 16 bytes
    const authTagLength =
      getUIntOption(options, 'authTagLength') !== -1
        ? getUIntOption(options, 'authTagLength')
        : 16;
    const args = {
      cipher_type: cipherType,
      cipher_key: cipherKeyBuffer,
      iv,
      ...options,
      auth_tag_len: authTagLength,
    };
    this.internal = isCipher
      ? createInternalCipher(args)
      : createInternalDecipher(args);
  }

  update(
    data: BinaryLike,
    inputEncoding?: CipherEncoding,
    outputEncoding?: CipherEncoding,
  ): ArrayBuffer | string {
    const defaultEncoding = getDefaultEncoding();
    inputEncoding = inputEncoding ?? defaultEncoding;
    outputEncoding = outputEncoding ?? defaultEncoding;

    if (typeof data === 'string') {
      validateEncoding(data, inputEncoding);
    } else if (!ArrayBuffer.isView(data)) {
      throw new Error('Invalid data argument');
    }

    if (typeof data === 'string') {
      // On node this is handled on the native side
      // on our case we need to correctly send the arraybuffer to the jsi side
      inputEncoding = inputEncoding === 'buffer' ? 'utf8' : inputEncoding;
      data = binaryLikeToArrayBuffer(data, inputEncoding);
    } else {
      data = binaryLikeToArrayBuffer(data as BinaryLikeNode, inputEncoding);
    }

    const ret = this.internal.update(data);

    if (outputEncoding && outputEncoding !== 'buffer') {
      this.decoder = getDecoder(this.decoder, outputEncoding);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return this.decoder!.write(SBuffer.from(ret) as any);
    }

    return ret;
  }

  final(): ArrayBuffer;
  final(outputEncoding: BufferEncoding | 'buffer'): string;
  final(outputEncoding?: BufferEncoding | 'buffer'): ArrayBuffer | string {
    const ret = this.internal.final();

    if (outputEncoding && outputEncoding !== 'buffer') {
      this.decoder = getDecoder(this.decoder, outputEncoding);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return this.decoder!.end(SBuffer.from(ret) as any);
    }

    return ret;
  }

  _transform(chunk: BinaryLike, encoding: Encoding, callback: () => void) {
    this.push(this.update(chunk, encoding));
    callback();
  }

  _flush(callback: () => void) {
    this.push(this.final());
    callback();
  }

  public setAutoPadding(autoPadding?: boolean): this {
    this.internal.setAutoPadding(!!autoPadding);
    return this;
  }

  public setAAD(
    buffer: Buffer,
    options?: {
      plaintextLength: number;
    },
  ): this {
    this.internal.setAAD({
      data: buffer.buffer,
      plaintextLength: options?.plaintextLength,
    });
    return this;
  }

  public getAuthTag(): ArrayBuffer {
    return this.internal.getAuthTag();
  }

  public setAuthTag(tag: Buffer): this {
    this.internal.setAuthTag(binaryLikeToArrayBuffer(tag));
    return this;
  }
}

class Cipher extends CipherCommon {
  constructor(
    cipherType: string,
    cipherKey: BinaryLikeNode,
    options: Record<string, TransformOptions> = {},
    iv?: BinaryLike | null,
  ) {
    if (iv != null) {
      iv = binaryLikeToArrayBuffer(iv);
    }
    super(cipherType, cipherKey, true, options, iv);
  }
}

class Decipher extends CipherCommon {
  constructor(
    cipherType: string,
    cipherKey: BinaryLikeNode,
    options: Record<string, TransformOptions> = {},
    iv?: BinaryLike | null,
  ) {
    if (iv != null) {
      iv = binaryLikeToArrayBuffer(iv);
    }

    super(cipherType, cipherKey, false, options, iv);
  }
}

export function createDecipher(
  algorithm: CipherCCMTypes,
  password: BinaryLikeNode,
  options: CipherCCMOptions,
): DecipherCCM;
export function createDecipher(
  algorithm: CipherGCMTypes,
  password: BinaryLikeNode,
  options?: CipherGCMOptions,
): DecipherGCM;
export function createDecipher(
  algorithm: CipherType,
  password: BinaryLikeNode,
  options?: Stream.TransformOptions,
): DecipherCCM | DecipherGCM | Decipher;
export function createDecipher(
  algorithm: string,
  password: BinaryLikeNode,
  options?: CipherCCMOptions | CipherGCMOptions | Stream.TransformOptions,
): DecipherCCM | DecipherGCM | Decipher {
  if (options === undefined) options = {};
  return new Decipher(
    algorithm,
    password,
    options as Record<string, TransformOptions>,
  );
}

export function createDecipheriv(
  algorithm: CipherCCMTypes,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options: CipherCCMOptions,
): DecipherCCM;
export function createDecipheriv(
  algorithm: CipherOCBTypes,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options: CipherOCBOptions,
): DecipherOCB;
export function createDecipheriv(
  algorithm: CipherGCMTypes,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options?: CipherGCMOptions,
): DecipherGCM;
export function createDecipheriv(
  algorithm: CipherType,
  key: BinaryLikeNode,
  iv: BinaryLike | null,
  options?: Stream.TransformOptions,
): DecipherCCM | DecipherOCB | DecipherGCM | Decipher;
export function createDecipheriv(
  algorithm: string,
  key: BinaryLikeNode,
  iv: BinaryLike | null,
  options?:
    | CipherCCMOptions
    | CipherOCBOptions
    | CipherGCMOptions
    | Stream.TransformOptions,
): DecipherCCM | DecipherOCB | DecipherGCM | Decipher {
  return new Decipher(
    algorithm,
    key,
    options as Record<string, TransformOptions>,
    iv,
  );
}

export function createCipher(
  algorithm: CipherCCMTypes,
  password: BinaryLikeNode,
  options: CipherCCMOptions,
): CipherCCM;
export function createCipher(
  algorithm: CipherGCMTypes,
  password: BinaryLikeNode,
  options?: CipherGCMOptions,
): CipherGCM;
export function createCipher(
  algorithm: CipherType,
  password: BinaryLikeNode,
  options?: Stream.TransformOptions,
): CipherCCM | CipherGCM | Cipher;
export function createCipher(
  algorithm: string,
  password: BinaryLikeNode,
  options?: CipherGCMOptions | CipherCCMOptions | Stream.TransformOptions,
): CipherCCM | CipherGCM | Cipher {
  return new Cipher(
    algorithm,
    password,
    options as Record<string, TransformOptions>,
  );
}

export function createCipheriv(
  algorithm: CipherCCMTypes,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options: CipherCCMOptions,
): CipherCCM;
export function createCipheriv(
  algorithm: CipherOCBTypes,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options: CipherOCBOptions,
): CipherOCB;
export function createCipheriv(
  algorithm: CipherGCMTypes,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options?: CipherGCMOptions,
): CipherGCM;
export function createCipheriv(
  algorithm: CipherType,
  key: BinaryLikeNode,
  iv: BinaryLike | null,
  options?: Stream.TransformOptions,
): CipherCCM | CipherOCB | CipherGCM | Cipher;
export function createCipheriv(
  algorithm: string,
  key: BinaryLikeNode,
  iv: BinaryLike | null,
  options?:
    | CipherCCMOptions
    | CipherOCBOptions
    | CipherGCMOptions
    | Stream.TransformOptions,
): CipherCCM | CipherOCB | CipherGCM | Cipher {
  return new Cipher(
    algorithm,
    key,
    options as Record<string, TransformOptions>,
    iv,
  );
}

// RSA Functions
// Follows closely the model implemented in node

function rsaFunctionFor(
  method: (
    data: ArrayBuffer,
    format: KFormatType,
    type: KeyEncoding | undefined,
    passphrase: BinaryLike | undefined,
    buffer: ArrayBuffer,
    padding: number,
    oaepHash: string | undefined,
    oaepLabel: BinaryLike | undefined,
  ) => Buffer,
  defaultPadding: number,
  keyType: 'public' | 'private',
) {
  return (options: EncodingOptions, buffer: BinaryLike) => {
    const { format, type, data, passphrase } =
      keyType === 'private'
        ? preparePrivateKey(options)
        : preparePublicOrPrivateKey(options);
    const padding = options.padding || defaultPadding;
    const { oaepHash, encoding } = options;
    let { oaepLabel } = options;
    if (oaepHash !== undefined) validateString(oaepHash, 'key.oaepHash');
    if (oaepLabel !== undefined)
      oaepLabel = binaryLikeToArrayBuffer(oaepLabel, encoding);
    buffer = binaryLikeToArrayBuffer(buffer, encoding);

    const rawRes = method(
      data,
      format,
      type,
      passphrase,
      buffer,
      padding,
      oaepHash,
      oaepLabel,
    );

    return Buffer.from(rawRes);
  };
}

export const publicEncrypt = rsaFunctionFor(
  _publicEncrypt,
  constants.RSA_PKCS1_OAEP_PADDING,
  'public',
);
export const publicDecrypt = rsaFunctionFor(
  _publicDecrypt,
  constants.RSA_PKCS1_PADDING,
  'public',
);
// const privateEncrypt = rsaFunctionFor(_privateEncrypt, constants.RSA_PKCS1_PADDING,
//   'private');
export const privateDecrypt = rsaFunctionFor(
  _privateDecrypt,
  constants.RSA_PKCS1_OAEP_PADDING,
  'private',
);

//                                   _       _  __          _____      _
//                                  | |     | |/ /         |  __ \    (_)
//    __ _  ___ _ __   ___ _ __ __ _| |_ ___| ' / ___ _   _| |__) |_ _ _ _ __
//   / _` |/ _ \ '_ \ / _ \ '__/ _` | __/ _ \  < / _ \ | | |  ___/ _` | | '__|
//  | (_| |  __/ | | |  __/ | | (_| | ||  __/ . \  __/ |_| | |  | (_| | | |
//   \__, |\___|_| |_|\___|_|  \__,_|\__\___|_|\_\___|\__, |_|   \__,_|_|_|
//    __/ |                                            __/ |
//   |___/                                            |___/
export type GenerateKeyPairOptions = {
  modulusLength?: number; // Key size in bits (RSA, DSA).
  publicExponent?: number; // Public exponent (RSA). Default: 0x10001.
  hashAlgorithm?: string; // Name of the message digest (RSA-PSS).
  mgf1HashAlgorithm?: string; // string Name of the message digest used by MGF1 (RSA-PSS).
  saltLength?: number; // Minimal salt length in bytes (RSA-PSS).
  divisorLength?: number; // Size of q in bits (DSA).
  namedCurve?: string; // Name of the curve to use (EC).
  prime?: Buffer; // The prime parameter (DH).
  primeLength?: number; // Prime length in bits (DH).
  generator?: number; // Custom generator (DH). Default: 2.
  groupName?: string; // Diffie-Hellman group name (DH). See crypto.getDiffieHellman().
  publicKeyEncoding?: EncodingOptions; // See keyObject.export().
  privateKeyEncoding?: EncodingOptions; // See keyObject.export().
  paramEncoding?: string;
  hash?: string;
  mgf1Hash?: string;
};

export type KeyPairKey = Buffer | KeyObjectHandle | CryptoKey | undefined;

export type GenerateKeyPairReturn = [
  error?: Error,
  privateKey?: KeyPairKey,
  publicKey?: KeyPairKey,
];

export type GenerateKeyPairCallback = (
  error?: Error,
  publicKey?: KeyPairKey,
  privateKey?: KeyPairKey,
) => GenerateKeyPairReturn | void;

export type KeyPair = {
  publicKey?: KeyPairKey;
  privateKey?: KeyPairKey;
};

export type GenerateKeyPairPromiseReturn = [error?: Error, keypair?: KeyPair];

function parseKeyEncoding(
  keyType: string,
  options: GenerateKeyPairOptions = kEmptyObject,
) {
  const { publicKeyEncoding, privateKeyEncoding } = options;

  let publicFormat, publicType;
  if (publicKeyEncoding == null) {
    publicFormat = publicType = undefined;
  } else if (typeof publicKeyEncoding === 'object') {
    ({ format: publicFormat, type: publicType } = parsePublicKeyEncoding(
      publicKeyEncoding,
      keyType,
      'publicKeyEncoding',
    ));
  } else {
    throw new Error(
      'Invalid argument options.publicKeyEncoding',
      publicKeyEncoding,
    );
  }

  let privateFormat, privateType, cipher, passphrase;
  if (privateKeyEncoding == null) {
    privateFormat = privateType = undefined;
  } else if (typeof privateKeyEncoding === 'object') {
    ({
      format: privateFormat,
      type: privateType,
      cipher,
      passphrase,
    } = parsePrivateKeyEncoding(
      privateKeyEncoding,
      keyType,
      'privateKeyEncoding',
    ));
  } else {
    throw new Error(
      'Invalid argument options.privateKeyEncoding',
      publicKeyEncoding as ErrorOptions,
    );
  }

  return [
    publicFormat,
    publicType,
    privateFormat,
    privateType,
    cipher,
    passphrase,
  ];
}

/** On node a very complex "job" chain is created, we are going for a far simpler approach and calling
 *  an internal function that basically executes the same byte shuffling on the native side
 */
function internalGenerateKeyPair(
  isAsync: boolean,
  type: KeyPairType,
  options?: GenerateKeyPairOptions,
  callback?: GenerateKeyPairCallback,
): GenerateKeyPairReturn | void {
  const encoding = parseKeyEncoding(type, options);

  // if (options !== undefined)
  //   validateObject(options, 'options');

  switch (type) {
    case 'rsa-pss':
    // fallthrough
    case 'rsa':
      return internalRsaGenerateKeyPair(
        isAsync,
        type,
        options,
        callback,
        encoding,
      );

    // case 'dsa': {
    //   validateObject(options, 'options');
    //   const { modulusLength } = options!;
    //   validateUint32(modulusLength, 'options.modulusLength');

    //   let { divisorLength } = options!;
    //   if (divisorLength == null) {
    //     divisorLength = -1;
    //   } else validateInt32(divisorLength, 'options.divisorLength', 0);

    //   // return new DsaKeyPairGenJob(
    //   //   mode,
    //   //   modulusLength,
    //   //   divisorLength,
    //   //   ...encoding);
    // }

    case 'ec':
      return internalEcGenerateKeyPair(
        isAsync,
        type,
        options,
        callback,
        encoding,
      );

    // case 'ed25519':
    // case 'ed448':
    // case 'x25519':
    // case 'x448': {
    //   let id;
    //   switch (type) {
    //     case 'ed25519':
    //       id = EVP_PKEY_ED25519;
    //       break;
    //     case 'ed448':
    //       id = EVP_PKEY_ED448;
    //       break;
    //     case 'x25519':
    //       id = EVP_PKEY_X25519;
    //       break;
    //     case 'x448':
    //       id = EVP_PKEY_X448;
    //       break;
    //   }
    //   return new NidKeyPairGenJob(mode, id, ...encoding);
    // }
    // case 'dh': {
    //   validateObject(options, 'options');
    //   const { group, primeLength, prime, generator } = options;
    //   if (group != null) {
    //     if (prime != null)
    //       throw new ERR_INCOMPATIBLE_OPTION_PAIR('group', 'prime');
    //     if (primeLength != null)
    //       throw new ERR_INCOMPATIBLE_OPTION_PAIR('group', 'primeLength');
    //     if (generator != null)
    //       throw new ERR_INCOMPATIBLE_OPTION_PAIR('group', 'generator');

    //     validateString(group, 'options.group');

    //     return new DhKeyPairGenJob(mode, group, ...encoding);
    //   }

    //   if (prime != null) {
    //     if (primeLength != null)
    //       throw new ERR_INCOMPATIBLE_OPTION_PAIR('prime', 'primeLength');

    //     validateBuffer(prime, 'options.prime');
    //   } else if (primeLength != null) {
    //     validateInt32(primeLength, 'options.primeLength', 0);
    //   } else {
    //     throw new ERR_MISSING_OPTION(
    //       'At least one of the group, prime, or primeLength options'
    //     );
    //   }

    //   if (generator != null) {
    //     validateInt32(generator, 'options.generator', 0);
    //   }
    //   return new DhKeyPairGenJob(
    //     mode,
    //     prime != null ? prime : primeLength,
    //     generator == null ? 2 : generator,
    //     ...encoding
    //   );
    // }
    default:
    // Fall through
  }
  const err = new Error(`
      Invalid Argument options: '${type}' scheme not supported for generateKey().
      Currently not all encryption methods are supported in quick-crypto.  Check
      implementation_coverage.md for status.
    `);
  return [err, undefined, undefined];
}

const internalRsaGenerateKeyPair = (
  isAsync: boolean,
  type: KeyPairType,
  options: GenerateKeyPairOptions | undefined,
  callback: GenerateKeyPairCallback | undefined,
  encoding: (string | ArrayBuffer | KFormatType | KeyEncoding | undefined)[],
): GenerateKeyPairReturn | void => {
  validateObject<GenerateKeyPairOptions>(options, 'options');
  const { modulusLength } = options!;
  validateUint32(modulusLength as number, 'options.modulusLength');
  let { publicExponent } = options!;
  if (publicExponent == null) {
    publicExponent = 0x10001;
  } else {
    validateUint32(publicExponent, 'options.publicExponent');
  }

  if (type === 'rsa') {
    if (isAsync) {
      NativeQuickCrypto.generateKeyPair(
        KeyVariant.RSA_SSA_PKCS1_v1_5, // Used also for RSA-OAEP
        modulusLength as number,
        publicExponent,
        ...encoding,
      )
        .then(([err, publicKey, privateKey]) => {
          if (publicKey instanceof Buffer) {
            publicKey = Buffer.from(publicKey);
          }
          if (privateKey instanceof Buffer) {
            privateKey = Buffer.from(privateKey);
          }
          callback!(err, publicKey, privateKey);
        })
        .catch((err) => {
          callback!(err, undefined, undefined);
        });
    } else {
      const [err, publicKey, privateKey] =
        NativeQuickCrypto.generateKeyPairSync(
          KeyVariant.RSA_SSA_PKCS1_v1_5,
          modulusLength as number,
          publicExponent,
          ...encoding,
        );

      const pub =
        publicKey instanceof Buffer ? Buffer.from(publicKey) : publicKey;
      const priv =
        privateKey instanceof Buffer ? Buffer.from(privateKey) : privateKey;
      return [err, pub, priv];
    }
  }

  const { hash, mgf1Hash, hashAlgorithm, mgf1HashAlgorithm, saltLength } =
    options!;

  // // We don't have a process object on RN
  // // const pendingDeprecation = getOptionValue('--pending-deprecation');

  if (saltLength !== undefined)
    validateInt32(saltLength, 'options.saltLength', 0);
  if (hashAlgorithm !== undefined)
    validateString(hashAlgorithm, 'options.hashAlgorithm');
  if (mgf1HashAlgorithm !== undefined)
    validateString(mgf1HashAlgorithm, 'options.mgf1HashAlgorithm');
  if (hash !== undefined) {
    // pendingDeprecation && process.emitWarning(
    //   '"options.hash" is deprecated, ' +
    //   'use "options.hashAlgorithm" instead.',
    //   'DeprecationWarning',
    //   'DEP0154');
    validateString(hash, 'options.hash');
    if (hashAlgorithm && hash !== hashAlgorithm) {
      throw new Error(`Invalid Argument options.hash ${hash}`);
    }
  }
  if (mgf1Hash !== undefined) {
    // pendingDeprecation && process.emitWarning(
    //   '"options.mgf1Hash" is deprecated, ' +
    //   'use "options.mgf1HashAlgorithm" instead.',
    //   'DeprecationWarning',
    //   'DEP0154');
    validateString(mgf1Hash, 'options.mgf1Hash');
    if (mgf1HashAlgorithm && mgf1Hash !== mgf1HashAlgorithm) {
      throw new Error(`Invalid Argument options.mgf1Hash ${mgf1Hash}`);
    }
  }

  return NativeQuickCrypto.generateKeyPairSync(
    KeyVariant.RSA_PSS,
    modulusLength as number,
    publicExponent,
    hashAlgorithm || hash,
    mgf1HashAlgorithm || mgf1Hash,
    saltLength,
    ...encoding,
  );
};

const internalEcGenerateKeyPair = (
  isAsync: boolean,
  _type: KeyPairType,
  options: GenerateKeyPairOptions | undefined,
  callback: GenerateKeyPairCallback | undefined,
  encoding: (string | ArrayBuffer | KFormatType | KeyEncoding | undefined)[],
): GenerateKeyPairReturn | void => {
  validateObject<GenerateKeyPairOptions>(options, 'options');
  const { namedCurve } = options!;
  validateString(namedCurve, 'options.namedCurve');
  let paramEncodingFlag = ECCurve.OPENSSL_EC_NAMED_CURVE;
  const { paramEncoding } = options!;
  if (paramEncoding == null || paramEncoding === 'named')
    paramEncodingFlag = ECCurve.OPENSSL_EC_NAMED_CURVE;
  else if (paramEncoding === 'explicit')
    paramEncodingFlag = ECCurve.OPENSSL_EC_EXPLICIT_CURVE;
  else
    throw new Error(`Invalid Argument options.paramEncoding ${paramEncoding}`);

  if (isAsync) {
    NativeQuickCrypto.generateKeyPair(
      KeyVariant.EC,
      namedCurve as NamedCurve,
      paramEncodingFlag,
      ...encoding,
    )
      .then(([err, publicKey, privateKey]) => {
        if (publicKey instanceof Buffer) {
          publicKey = Buffer.from(publicKey);
        }
        if (privateKey instanceof Buffer) {
          privateKey = Buffer.from(privateKey);
        }
        callback?.(err, publicKey, privateKey);
      })
      .catch((err) => {
        callback?.(err, undefined, undefined);
      });
  }

  const [err, publicKey, privateKey] = NativeQuickCrypto.generateKeyPairSync(
    KeyVariant.EC,
    namedCurve as NamedCurve,
    paramEncodingFlag,
    ...encoding,
  );
  const pub = publicKey instanceof Buffer ? Buffer.from(publicKey) : publicKey;
  const priv =
    privateKey instanceof Buffer ? Buffer.from(privateKey) : privateKey;
  return [err, pub, priv];
};

export const generateKeyPair = (
  type: KeyPairType,
  options: GenerateKeyPairOptions,
  callback: GenerateKeyPairCallback,
): void => {
  validateFunction(callback);
  internalGenerateKeyPair(true, type, options, callback);
};

// Promisify generateKeyPair
// (attempted to use util.promisify, to no avail)
export const generateKeyPairPromise = (
  type: KeyPairType,
  options: GenerateKeyPairOptions,
): Promise<GenerateKeyPairPromiseReturn> => {
  return new Promise((resolve, reject) => {
    generateKeyPair(type, options, (err, publicKey, privateKey) => {
      if (err) {
        reject([err, undefined]);
      } else {
        resolve([undefined, { publicKey, privateKey }]);
      }
    });
  });
};

// generateKeyPairSync
export function generateKeyPairSync(type: KeyPairType): CryptoKeyPair;
export function generateKeyPairSync(
  type: KeyPairType,
  options: GenerateKeyPairOptions,
): CryptoKeyPair;
export function generateKeyPairSync(
  type: KeyPairType,
  options?: GenerateKeyPairOptions,
): CryptoKeyPair {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [_, publicKey, privateKey] = internalGenerateKeyPair(
    false,
    type,
    options,
    undefined,
  )!;

  return {
    publicKey,
    privateKey,
  };
}
