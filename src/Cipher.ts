import { NativeFastCrypto } from './NativeFastCrypto/NativeFastCrypto';
import Stream from 'stream';
import { Buffer } from '@craftzdog/react-native-buffer';
import { BinaryLike, binaryLikeToArrayBuffer, Encoding } from './Utils';
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

function getUIntOption(options?: Record<string, any>, key: string) {
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
  _transform(
    chunk: string | BinaryLike,
    encoding: Encoding,
    callback: () => void
  ) {
    NativeFastCrypto.cipher.update(chunk, encoding);
    callback();
  }

  _flush(callback: () => void) {
    this.push(this.final());
    callback();
  }

  update(data: BinaryLike);
  update(data: string, inputEncoding: Encoding): Buffer;
  update(
    data: ArrayBufferView,
    inputEncoding: undefined,
    outputEncoding: Encoding
  ): string;
  update(
    data: string,
    inputEncoding: Encoding | undefined,
    outputEncoding: Encoding
  ): string;
  update(
    data: string | ArrayBufferView | BinaryLike,
    inputEncoding?: Encoding,
    outputEncoding?: Encoding
  ) {}

  final(): Buffer;
  final(outputEncoding: BufferEncoding): string;
  final(arg: undefined | BufferEncoding): Buffer | string {}

  setAutoPadding(autoPadding?: boolean): this {
    NativeFastCrypto.cipher.setAutoPadding(!!autoPadding);
    return this;
  }

  protected setAAD(
    buffer: ArrayBufferView,
    options?: {
      plaintextLength: number;
    }
  ): this {
    NativeFastCrypto.cipher.setAAD(buffer.buffer, options?.plaintextLength);
    return this;
  }

  protected getAuthTag(): Buffer {
    return Buffer.from(NativeFastCrypto.cipher.getAuthTag());
  }
}

class Cipher extends CipherCommon {
  private internal: InternalCipher;
  private options: any;
  constructor(
    cipherType: string,
    cipherKey: string,
    options: Record<string, any> = {}
  ) {
    super(options);
    const cipherKeyBuffer = binaryLikeToArrayBuffer(cipherKey);
    // TODO(osp) This might not be smart, check again after release
    const authTagLength = getUIntOption(options, 'authTagLength');
    this.internal = createInternalCipher({
      cipher_type: cipherType,
      cipher_key: cipherKeyBuffer,
      ...options,
      auth_tag_len: authTagLength,
    });
    this.options = options;
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

class Decipher extends CipherCommon {}

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
): Decipher;

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
