/* eslint-disable no-dupe-class-members */
import { NativeFastCrypto } from './NativeFastCrypto/NativeFastCrypto';
import Stream from 'stream';
import {
  BinaryLike,
  binaryLikeToArrayBuffer,
  CipherEncoding,
  Encoding,
  getDefaultEncoding,
} from './Utils';
import type { InternalCipher } from './NativeFastCrypto/cipher';
// TODO(osp) re-enable type specific constructors
// They are nice to have but not absolutely necessary
// import type {
//   CipherCCMOptions,
//   CipherCCMTypes,
//   CipherGCMTypes,
//   CipherGCMOptions,
//   // CipherKey,
//   // KeyObject,
//   // TODO @Szymon20000 This types seem to be missing? Where did you get this definitions from?
//   // CipherOCBTypes,
//   // CipherOCBOptions,
// } from 'crypto'; // Node crypto typings
import { StringDecoder } from 'string_decoder';
import type { Buffer } from '@craftzdog/react-native-buffer';
import { Buffer as SBuffer } from 'safe-buffer';

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
