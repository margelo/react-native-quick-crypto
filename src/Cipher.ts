/* eslint-disable no-dupe-class-members */
import { NativeFastCrypto } from './NativeFastCrypto/NativeFastCrypto';
import Stream from 'stream';
import { Buffer } from '@craftzdog/react-native-buffer';
import {
  ab2str,
  BinaryLike,
  binaryLikeToArrayBuffer,
  CipherEncoding,
  Encoding,
  getDefaultEncoding,
} from './Utils';
import type { InternalCipher } from './NativeFastCrypto/cipher';
import type {
  CipherCCMOptions,
  CipherCCMTypes,
  CipherGCMTypes,
  CipherGCMOptions,
  // CipherKey,
  // KeyObject,
  // TODO @Szymon20000 This types seem to be missing? Where did you get this definitions from?
  // CipherOCBTypes,
  // CipherOCBOptions,
} from 'crypto'; // Node crypto typings

const createInternalCipher = NativeFastCrypto.createCipher;
const createInternalDecipher = NativeFastCrypto.createDecipher;

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

class CipherCommon extends Stream.Transform {
  private internal: InternalCipher;
  private options: any;

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
    this.options = options;
  }

  // TODO(osp) missing function
  // function validateEncoding(data, encoding) {
  //   const normalizedEncoding = normalizeEncoding(encoding);
  //   const length = data.length;

  //   if (normalizedEncoding === 'hex' && length % 2 !== 0) {
  //     throw new ERR_INVALID_ARG_VALUE('encoding', encoding,
  //                                     `is invalid for data of length ${length}`);
  //   }
  // }

  update(
    data: BinaryLike | ArrayBufferView,
    inputEncoding?: CipherEncoding,
    outputEncoding?: CipherEncoding
  ): ArrayBuffer | string {
    console.warn('mmk1');

    const defaultEncoding = getDefaultEncoding();
    inputEncoding = inputEncoding ?? defaultEncoding;
    outputEncoding = outputEncoding ?? defaultEncoding;
    console.warn('mmk2');

    // TODO(osp) validation
    // if (typeof data === 'string') {
    // validateEncoding(data, inputEncoding);
    // } else if (!isArrayBufferView(data)) {
    // throw new ERR_INVALID_ARG_TYPE(
    //   'data', ['string', 'Buffer', 'TypedArray', 'DataView'], data);
    // }

    if (typeof data === 'string') {
      console.warn('mmk3');
      data = binaryLikeToArrayBuffer(data, inputEncoding);
    }
    console.warn('mmk4');

    const ret = this.internal.update(data);

    console.warn('mmk5');
    if (outputEncoding && outputEncoding !== 'buffer') {
      return ab2str(ret, outputEncoding);
    }
    console.warn('mmk6');

    return ret;
  }

  final(): ArrayBuffer;
  final(outputEncoding: BufferEncoding | 'buffer'): string;
  final(outputEncoding?: BufferEncoding | 'buffer'): ArrayBuffer | string {
    const ret = this.internal.final(outputEncoding);

    if (outputEncoding && outputEncoding !== 'buffer') {
      return ab2str(ret, outputEncoding);
    }

    return ret;
  }

  _transform(chunk: BinaryLike, encoding: Encoding, callback: () => void) {
    // this.update(chunk, encoding);
    callback();
  }

  _flush(callback: () => void) {
    this.push(this.final());
    callback();
  }

  setAutoPadding(autoPadding?: boolean): this {
    this.internal.setAutoPadding(!!autoPadding);
    return this;
  }

  protected setAAD(
    buffer: ArrayBufferView,
    options?: {
      plaintextLength: number;
    }
  ): this {
    this.internal.setAAD(buffer.buffer, options?.plaintextLength);
    return this;
  }

  protected getAuthTag(): Buffer {
    return Buffer.from(this.internal.getAuthTag());
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

export function createDecipher(
  algorithm: CipherCCMTypes,
  password: BinaryLike,
  options: CipherCCMOptions
): Decipher;
export function createDecipher(
  algorithm: CipherGCMTypes,
  password: BinaryLike,
  options?: CipherGCMOptions
): Decipher;
export function createDecipher(
  algorithm: string,
  password: BinaryLike,
  options?: Stream.TransformOptions
): Decipher {
  return new Decipher(algorithm, password, options);
}

export function createDecipheriv(
  algorithm: CipherCCMTypes,
  key: BinaryLike,
  iv: BinaryLike,
  options: CipherCCMOptions
): Decipher;
// export function createDecipheriv(
//   algorithm: CipherOCBTypes,
//   key: BinaryLike,
//   iv: BinaryLike,
//   options: CipherOCBOptions
// ): DecipherOCB;
export function createDecipheriv(
  algorithm: CipherGCMTypes,
  key: BinaryLike,
  iv: BinaryLike,
  options?: CipherGCMOptions
): Decipher;
export function createDecipheriv(
  algorithm: string,
  key: BinaryLike,
  iv: BinaryLike | null,
  options?: Stream.TransformOptions
): Decipher {
  return new Decipher(algorithm, key, options, iv);
}

export function createCipher(
  algorithm: CipherCCMTypes,
  password: BinaryLike,
  options: CipherCCMOptions
): Cipher;
export function createCipher(
  algorithm: CipherGCMTypes,
  password: BinaryLike,
  options?: CipherGCMOptions
): Cipher;
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
export function createCipheriv(
  algorithm: CipherCCMTypes,
  key: BinaryLike,
  iv: BinaryLike,
  options: CipherCCMOptions
): Cipher;
// export function createCipheriv(
//   algorithm: CipherOCBTypes,
//   key: BinaryLike,
//   iv: BinaryLike,
//   options: CipherOCBOptions
// ): CipherOCB;
export function createCipheriv(
  algorithm: CipherGCMTypes,
  key: BinaryLike,
  iv: BinaryLike,
  options?: CipherGCMOptions
): Cipher;
export function createCipheriv(
  algorithm: string,
  key: BinaryLike,
  iv: BinaryLike | null,
  options?: Stream.TransformOptions
): Cipher {
  return new Cipher(algorithm, key, options, iv);
}
