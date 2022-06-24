/* eslint-disable no-dupe-class-members */
import { NativeQuickCrypto } from './NativeQuickCrypto/NativeQuickCrypto';
import Stream from 'stream';
import {
  BinaryLike,
  binaryLikeToArrayBuffer,
  CipherEncoding,
  Encoding,
  getDefaultEncoding,
  kEmptyObject,
  validateFunction,
  validateObject,
  validateString,
  validateUint32,
} from './Utils';
import { InternalCipher, RSAKeyVariant } from './NativeQuickCrypto/Cipher';
// TODO(osp) re-enable type specific constructors
// They are nice to have but not absolutely necessary
// import type {
//   CipherCCMOptions,
//   CipherCCMTypes,
//   CipherGCMTypes,
//   CipherGCMOptions,
//   // CipherKey,
//   // KeyObject,
//   // TODO(Szymon) This types seem to be missing? Where did you get this definitions from?
//   // CipherOCBTypes,
//   // CipherOCBOptions,
// } from 'crypto'; // Node crypto typings
import { StringDecoder } from 'string_decoder';
import type { Buffer } from '@craftzdog/react-native-buffer';
import { Buffer as SBuffer } from 'safe-buffer';
import { constants } from './constants';
import {
  parsePrivateKeyEncoding,
  parsePublicKeyEncoding,
  preparePrivateKey,
  preparePublicOrPrivateKey,
} from './keys';

const createInternalCipher = NativeQuickCrypto.createCipher;
const createInternalDecipher = NativeQuickCrypto.createDecipher;
const _publicEncrypt = NativeQuickCrypto.publicEncrypt;
const _publicDecrypt = NativeQuickCrypto.publicDecrypt;

function getUIntOption(options: Record<string, any>, key: string) {
  let value;
  if (options && (value = options[key]) != null) {
    // >>> Turns any type into a positive integer (also sets the sign bit to 0)
    // eslint-disable-next-line no-bitwise
    if (value >>> 0 !== value) throw new Error(`options.${key}: ${value}`);
    return value;
  }
  return -1;
}

function normalizeEncoding(enc: string) {
  if (!enc) return 'utf8';
  var retried;
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
    cipherKey: BinaryLike,
    isCipher: boolean,
    options: Record<string, any> = {},
    iv?: BinaryLike | null
  ) {
    super(options);
    const cipherKeyBuffer = binaryLikeToArrayBuffer(cipherKey);
    // TODO(osp) This might not be smart, check again after release
    const authTagLength = getUIntOption(options, 'authTagLength');
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
    outputEncoding?: CipherEncoding
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
      data = binaryLikeToArrayBuffer(data as any, inputEncoding);
    }

    const ret = this.internal.update(data);

    if (outputEncoding && outputEncoding !== 'buffer') {
      this.decoder = getDecoder(this.decoder, outputEncoding);

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
    }
  ): this {
    this.internal.setAAD({
      data: buffer.buffer,
      plaintextLength: options?.plaintextLength,
    });
    return this;
  }

  // protected getAuthTag(): Buffer {
  //   return Buffer.from(this.internal.getAuthTag());
  // }

  public setAuthTag(tag: Buffer): this {
    this.internal.setAuthTag(tag.buffer);
    return this;
  }
}

class Cipher extends CipherCommon {
  constructor(
    cipherType: string,
    cipherKey: BinaryLike,
    options: Record<string, any> = {},
    iv?: BinaryLike | null
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
    cipherKey: BinaryLike,
    options: Record<string, any> = {},
    iv?: BinaryLike | null
  ) {
    if (iv != null) {
      iv = binaryLikeToArrayBuffer(iv);
    }

    super(cipherType, cipherKey, false, options, iv);
  }
}

// TODO(osp) This definitions cause typescript errors when using the API
// export function createDecipher(
//   algorithm: CipherCCMTypes,
//   password: BinaryLike,
//   options: CipherCCMOptions
// ): Decipher;
// export function createDecipher(
//   algorithm: CipherGCMTypes,
//   password: BinaryLike,
//   options?: CipherGCMOptions
// ): Decipher;
export function createDecipher(
  algorithm: string,
  password: BinaryLike,
  options?: Stream.TransformOptions
): Decipher {
  return new Decipher(algorithm, password, options);
}

// TODO(osp) This definitions cause typescript errors when using the API
// export function createDecipheriv(
//   algorithm: CipherCCMTypes,
//   key: BinaryLike,
//   iv: BinaryLike,
//   options: CipherCCMOptions
// ): Decipher;
// export function createDecipheriv(
//   algorithm: CipherOCBTypes,
//   key: BinaryLike,
//   iv: BinaryLike,
//   options: CipherOCBOptions
// ): DecipherOCB;
// export function createDecipheriv(
//   algorithm: CipherGCMTypes,
//   key: BinaryLike,
//   iv: BinaryLike,
//   options?: CipherGCMOptions
// ): Decipher;
export function createDecipheriv(
  algorithm: string,
  key: BinaryLike,
  iv: BinaryLike | null,
  options?: Stream.TransformOptions
): Decipher {
  return new Decipher(algorithm, key, options, iv);
}

// TODO(osp) This definitions cause typescript errors when using the API
// commenting them out for now
// export function createCipher(
//   algorithm: CipherCCMTypes,
//   password: BinaryLike,
//   options: CipherCCMOptions
// ): Cipher;
// export function createCipher(
//   algorithm: CipherGCMTypes,
//   password: BinaryLike,
//   options?: CipherGCMOptions
// ): Cipher;
export function createCipher(
  algorithm: string,
  password: BinaryLike,
  options?: Stream.TransformOptions
): Cipher {
  return new Cipher(algorithm, password, options);
}

// TODO(osp) on all the createCipheriv methods, node seems to use a "KeyObject" is seems to be a thread safe
// object that creates keys and what not. Not sure if we should support it.
// Fow now I replaced all of them to BinaryLike
// export function createCipheriv(
//   algorithm: CipherCCMTypes,
//   key: BinaryLike,
//   iv: BinaryLike,
//   options: CipherCCMOptions
// ): Cipher;
// export function createCipheriv(
//   algorithm: CipherOCBTypes,
//   key: BinaryLike,
//   iv: BinaryLike,
//   options: CipherOCBOptions
// ): CipherOCB;
// export function createCipheriv(
//   algorithm: CipherGCMTypes,
//   key: BinaryLike,
//   iv: BinaryLike,
//   options?: CipherGCMOptions
// ): Cipher;
export function createCipheriv(
  algorithm: string,
  key: BinaryLike,
  iv: BinaryLike | null,
  options?: Stream.TransformOptions
): Cipher {
  return new Cipher(algorithm, key, options, iv);
}

// RSA Functions
// Follows closely the model implemented in node

// TODO(osp) types...
function rsaFunctionFor(
  method: (
    data: ArrayBuffer,
    format: number,
    type: any,
    passphrase: any,
    buffer: ArrayBuffer,
    padding: number,
    oaepHash: any,
    oaepLabel: any
  ) => ArrayBuffer,
  defaultPadding: number,
  keyType: 'public' | 'private'
) {
  return (
    options: {
      key: any;
      encoding?: string;
      format?: any;
      padding?: any;
      oaepHash?: any;
      oaepLabel?: any;
    },
    buffer: BinaryLike
  ) => {
    console.warn('publicEncrypt called');
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

    console.warn('calling method with', data, format, type, passphrase);
    return method(
      data,
      format,
      type,
      passphrase,
      buffer,
      padding,
      oaepHash,
      oaepLabel
    );
  };
}

export const publicEncrypt = rsaFunctionFor(
  _publicEncrypt,
  constants.RSA_PKCS1_OAEP_PADDING,
  'public'
);
export const publicDecrypt = rsaFunctionFor(
  _publicDecrypt,
  constants.RSA_PKCS1_PADDING,
  'public'
);

//                                   _       _  __          _____      _
//                                  | |     | |/ /         |  __ \    (_)
//    __ _  ___ _ __   ___ _ __ __ _| |_ ___| ' / ___ _   _| |__) |_ _ _ _ __
//   / _` |/ _ \ '_ \ / _ \ '__/ _` | __/ _ \  < / _ \ | | |  ___/ _` | | '__|
//  | (_| |  __/ | | |  __/ | | (_| | ||  __/ . \  __/ |_| | |  | (_| | | |
//   \__, |\___|_| |_|\___|_|  \__,_|\__\___|_|\_\___|\__, |_|   \__,_|_|_|
//    __/ |                                            __/ |
//   |___/                                            |___/
type GenerateKeyPairOptions = {
  modulusLength: number; // Key size in bits (RSA, DSA).
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
  publicKeyEncoding?: any; // See keyObject.export().
  privateKeyEncoding?: any; // See keyObject.export().
  paramEncoding?: string;
  hash?: any;
  mgf1Hash?: any;
};
type GenerateKeyPairCallback = (
  error: unknown | null,
  publicKey?: Buffer,
  privateKey?: Buffer
) => void;

function parseKeyEncoding(
  keyType: string,
  options: GenerateKeyPairOptions = kEmptyObject
) {
  const { publicKeyEncoding, privateKeyEncoding } = options;

  let publicFormat, publicType;
  if (publicKeyEncoding == null) {
    publicFormat = publicType = undefined;
  } else if (typeof publicKeyEncoding === 'object') {
    ({ format: publicFormat, type: publicType } = parsePublicKeyEncoding(
      publicKeyEncoding,
      keyType,
      'publicKeyEncoding'
    ));
  } else {
    throw new Error(
      'Invalid argument options.publicKeyEncoding',
      publicKeyEncoding
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
      'privateKeyEncoding'
    ));
  } else {
    throw new Error(
      'Invalid argument options.privateKeyEncoding',
      publicKeyEncoding
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

function internalGenerateKeyPair(
  type: string,
  options: GenerateKeyPairOptions | undefined,
  callback: GenerateKeyPairCallback | undefined
) {
  // On node a very complex "job" chain is created, we are going for a far simpler approach and calling
  // an internal function that basically executes the same byte shuffling on the native side
  const encoding = parseKeyEncoding(type, options);

  // if (options !== undefined)
  //   validateObject(options, 'options');

  switch (type) {
    // case 'rsa-pss':
    case 'rsa': {
      validateObject<GenerateKeyPairOptions>(options, 'options');
      const { modulusLength } = options!;
      validateUint32(modulusLength, 'options.modulusLength');

      let { publicExponent } = options!;
      if (publicExponent == null) {
        publicExponent = 0x10001;
      } else {
        validateUint32(publicExponent, 'options.publicExponent');
      }

      // if (type === 'rsa') {
      const res = NativeQuickCrypto.generateKeyPair(
        true,
        RSAKeyVariant.kKeyVariantRSA_SSA_PKCS1_v1_5,
        modulusLength,
        publicExponent,
        ...encoding
      );

      callback?.(...res);

      return res;
      // }

      // const { hash, mgf1Hash, hashAlgorithm, mgf1HashAlgorithm, saltLength } =
      //   options!;

      // // We don't have a process object on RN
      // // const pendingDeprecation = getOptionValue('--pending-deprecation');

      // if (saltLength !== undefined)
      //   validateInt32(saltLength, 'options.saltLength', 0);
      // if (hashAlgorithm !== undefined)
      //   validateString(hashAlgorithm, 'options.hashAlgorithm');
      // if (mgf1HashAlgorithm !== undefined)
      //   validateString(mgf1HashAlgorithm, 'options.mgf1HashAlgorithm');
      // if (hash !== undefined) {
      //   // pendingDeprecation && process.emitWarning(
      //   //   '"options.hash" is deprecated, ' +
      //   //   'use "options.hashAlgorithm" instead.',
      //   //   'DeprecationWarning',
      //   //   'DEP0154');
      //   validateString(hash, 'options.hash');
      //   if (hashAlgorithm && hash !== hashAlgorithm) {
      //     throw new Error(`Invalid Argument options.hash ${hash}`);
      //   }
      // }
      // if (mgf1Hash !== undefined) {
      //   // pendingDeprecation && process.emitWarning(
      //   //   '"options.mgf1Hash" is deprecated, ' +
      //   //   'use "options.mgf1HashAlgorithm" instead.',
      //   //   'DeprecationWarning',
      //   //   'DEP0154');
      //   validateString(mgf1Hash, 'options.mgf1Hash');
      //   if (mgf1HashAlgorithm && mgf1Hash !== mgf1HashAlgorithm) {
      //     throw new Error(`Invalid Argument options.mgf1Hash ${mgf1Hash}`);
      //   }
      // }

      // return new RsaKeyPairGenJob(
      //   mode,
      //   kKeyVariantRSA_PSS,
      //   modulusLength,
      //   publicExponent,
      //   hashAlgorithm || hash,
      //   mgf1HashAlgorithm || mgf1Hash,
      //   saltLength,
      //   ...encoding);
    }
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
    // case 'ec': {
    //   validateObject(options, 'options');
    //   const { namedCurve } = options!;
    //   validateString(namedCurve, 'options.namedCurve');
    //   let { paramEncoding } = options!;
    //   if (paramEncoding == null || paramEncoding === 'named')
    //     paramEncoding = OPENSSL_EC_NAMED_CURVE;
    //   else if (paramEncoding === 'explicit')
    //     paramEncoding = OPENSSL_EC_EXPLICIT_CURVE;
    //   else
    //   throw new Error(`Invalid Argument options.paramEncoding ${paramEncoding}`);
    //     // throw new ERR_INVALID_ARG_VALUE('options.paramEncoding', paramEncoding);

    //   // return new EcKeyPairGenJob(mode, namedCurve, paramEncoding, ...encoding);
    // }
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
  throw new Error(
    `Invalid Argument options, currently not all encryption methods are supported in quick-crypto!`
  );
}

// TODO(osp) put correct types (e.g. type -> 'rsa', etc..)
export function generateKeyPair(
  type: string,
  callback: GenerateKeyPairCallback
): void;
export function generateKeyPair(
  type: string,
  options: GenerateKeyPairOptions,
  callback: GenerateKeyPairCallback
): void;
export function generateKeyPair(
  type: string,
  options?: GenerateKeyPairCallback | GenerateKeyPairOptions,
  callback?: GenerateKeyPairCallback
) {
  if (typeof options === 'function') {
    callback = options;
    options = undefined;
  }

  validateFunction(callback);

  internalGenerateKeyPair(type, options, callback);
}

export function generateKeyPairSync(type: string): {
  publicKey: any;
  privateKey: any;
};
export function generateKeyPairSync(
  type: string,
  options: GenerateKeyPairOptions
): { publicKey: any; privateKey: any };
export function generateKeyPairSync(
  type: string,
  options?: GenerateKeyPairOptions
): { publicKey: any; privateKey: any } {
  const [_, publicKey, privateKey] = internalGenerateKeyPair(
    type,
    options,
    undefined
  );

  return {
    publicKey,
    privateKey,
  };
}
