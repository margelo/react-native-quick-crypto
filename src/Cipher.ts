/* eslint-disable no-dupe-class-members */
import { NativeFastCrypto } from './NativeFastCrypto/NativeFastCrypto';
import Stream from 'stream';
import { Buffer } from '@craftzdog/react-native-buffer';
import {
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
  CipherKey,
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
    if (value >>> 0 !== value) throw new Error(`options.${key}`, value);
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
    options: Record<string, any> = {}
  ) {
    super(options);
    const cipherKeyBuffer = binaryLikeToArrayBuffer(cipherKey);
    // TODO(osp) This might not be smart, check again after release
    const authTagLength = getUIntOption(options, 'authTagLength');
    const args = {
      cipher_type: cipherType,
      cipher_key: cipherKeyBuffer,
      ...options,
      auth_tag_len: authTagLength,
    };
    this.internal = isCipher
      ? createInternalCipher(args)
      : createInternalDecipher(args);
    this.options = options;
  }

  _transform(
    chunk: string | BinaryLike,
    encoding: Encoding,
    callback: () => void
  ) {
    this.internal.update(chunk, encoding);
    callback();
  }

  _flush(callback: () => void) {
    this.push(this.final());
    callback();
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
    data: string | ArrayBufferView | BinaryLike,
    inputEncoding?: CipherEncoding,
    outputEncoding?: CipherEncoding
  ) {
    const defaultEncoding = getDefaultEncoding();
    inputEncoding = inputEncoding ?? defaultEncoding;
    outputEncoding = outputEncoding ?? defaultEncoding;

    // TODO(osp) validation
    // if (typeof data === 'string') {
    // validateEncoding(data, inputEncoding);
    // } else if (!isArrayBufferView(data)) {
    // throw new ERR_INVALID_ARG_TYPE(
    //   'data', ['string', 'Buffer', 'TypedArray', 'DataView'], data);
    // }

    if (typeof data === 'string') {
      data = binaryLikeToArrayBuffer(data);
    }

    const ret = this.internal.update(data, inputEncoding);

    if (outputEncoding && outputEncoding !== 'buffer') {
      // this._decoder = getDecoder(this._decoder, outputEncoding);
      // return this._decoder.write(ret);
    }

    return ret;
  }

  final(): ArrayBuffer;
  final(outputEncoding: BufferEncoding): string;
  final(arg: undefined | BufferEncoding): ArrayBuffer | string {
    return this.internal.final(arg);
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
    options: Record<string, any> = {}
  ) {
    super(cipherType, cipherKey, true, options);
  }
}

class CipherCCM extends Cipher {
  setAAD(
    buffer: ArrayBufferView,
    options: {
      plaintextLength: number;
    }
  ): this {
    super.setAAD(buffer, options);
    return this;
  }
  getAuthTag(): Buffer {
    return super.getAuthTag();
  }
}

class CipherGCM extends Cipher {
  setAAD(
    buffer: ArrayBufferView,
    options: {
      plaintextLength: number;
    }
  ): this {
    super.setAAD(buffer, options);
    return this;
  }
  getAuthTag(): Buffer {
    return super.getAuthTag();
  }
}

// class CipherOCB extends Cipher {
//   setAAD(
//     buffer: ArrayBufferView,
//     options: {
//       plaintextLength: number;
//     }
//   ): this {
//     super.setAAD(buffer, options);
//     return this;
//   }
//   getAuthTag(): Buffer {
//     return super.getAuthTag();
//   }
// }

class Decipher extends CipherCommon {
  constructor(
    cipherType: string,
    cipherKey: BinaryLike,
    options: Record<string, any> = {}
  ) {
    super(cipherType, cipherKey, false, options);
  }
}

class DecipherCCM extends Decipher {
  setAAD(
    buffer: ArrayBufferView,
    options: {
      plaintextLength: number;
    }
  ): this {
    super.setAAD(buffer, options);
    return this;
  }
  getAuthTag(): Buffer {
    return super.getAuthTag();
  }
}

class DecipherGCM extends Decipher {
  setAAD(
    buffer: ArrayBufferView,
    options: {
      plaintextLength: number;
    }
  ): this {
    super.setAAD(buffer, options);
    return this;
  }
  getAuthTag(): Buffer {
    return super.getAuthTag();
  }
}

// class DecipherOCB extends Decipher {
//   setAAD(
//     buffer: ArrayBufferView,
//     options: {
//       plaintextLength: number;
//     }
//   ): this {
//     super.setAAD(buffer, options);
//     return this;
//   }
//   getAuthTag(): Buffer {
//     return super.getAuthTag();
//   }
// }

export function createDecipher(
  algorithm: CipherCCMTypes,
  password: BinaryLike,
  options: CipherCCMOptions
): DecipherCCM;
export function createDecipher(
  algorithm: CipherGCMTypes,
  password: BinaryLike,
  options?: CipherGCMOptions
): DecipherGCM;
export function createDecipher(
  algorithm: string,
  password: BinaryLike,
  options?: Stream.TransformOptions
): Decipher {
  return new Decipher(algorithm, password, options);
}

export function createDecipheriv(
  algorithm: CipherCCMTypes,
  key: CipherKey,
  iv: BinaryLike,
  options: CipherCCMOptions
): DecipherCCM;
// export function createDecipheriv(
//   algorithm: CipherOCBTypes,
//   key: CipherKey,
//   iv: BinaryLike,
//   options: CipherOCBOptions
// ): DecipherOCB;
export function createDecipheriv(
  algorithm: CipherGCMTypes,
  key: CipherKey,
  iv: BinaryLike,
  options?: CipherGCMOptions
): DecipherGCM;
export function createDecipheriv(
  algorithm: string,
  key: CipherKey,
  iv: BinaryLike | null,
  options?: Stream.TransformOptions
): Decipher;

export function createCipher(
  algorithm: CipherCCMTypes,
  password: BinaryLike,
  options: CipherCCMOptions
): CipherCCM;
export function createCipher(
  algorithm: CipherGCMTypes,
  password: BinaryLike,
  options?: CipherGCMOptions
): CipherGCM;
export function createCipher(
  algorithm: string,
  password: BinaryLike,
  options?: Stream.TransformOptions
): Cipher {
  return new Cipher(algorithm, password, options);
}

export function createCipheriv(
  algorithm: CipherCCMTypes,
  key: CipherKey,
  iv: BinaryLike,
  options: CipherCCMOptions
): CipherCCM;
// export function createCipheriv(
//   algorithm: CipherOCBTypes,
//   key: CipherKey,
//   iv: BinaryLike,
//   options: CipherOCBOptions
// ): CipherOCB;
export function createCipheriv(
  algorithm: CipherGCMTypes,
  key: CipherKey,
  iv: BinaryLike,
  options?: CipherGCMOptions
): CipherGCM;
export function createCipheriv(
  algorithm: string,
  key: CipherKey,
  iv: BinaryLike | null,
  options?: Stream.TransformOptions
): Cipher;
