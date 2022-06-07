import { NativeFastCrypto } from './NativeFastCrypto/NativeFastCrypto';
import Stream from 'stream';
import { Buffer } from '@craftzdog/react-native-buffer';
import type { BinaryLike, Encoding } from './Utils';
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

class Cipher extends CipherCommon {}

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
  options?: stream.TransformOptions
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
  options?: stream.TransformOptions
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
  options?: stream.TransformOptions
): Cipher;

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
  options?: stream.TransformOptions
): Cipher;
