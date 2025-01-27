import { NitroModules } from 'react-native-nitro-modules';
import Stream, { type TransformOptions } from 'readable-stream';
import { Buffer } from '@craftzdog/react-native-buffer';
import type {
  CipherCCMOptions,
  CipherCCMTypes,
  CipherGCMTypes,
  CipherGCMOptions,
  CipherOCBOptions,
  CipherOCBTypes,
} from 'crypto'; // @types/node
import type { Cipher as NativeCipher } from './specs/cipher.nitro';
import { ab2str, binaryLikeToArrayBuffer } from './utils';
import type { BinaryLike, BinaryLikeNode, Encoding } from './utils';
import {
  getDefaultEncoding,
  getUIntOption,
  normalizeEncoding,
  validateEncoding,
} from './utils/cipher';

class CipherUtils {
  private static native =
    NitroModules.createHybridObject<NativeCipher>('Cipher');
  public static getSupportedCiphers(): string[] {
    return this.native.getSupportedCiphers();
  }
}

export function getCiphers(): string[] {
  return CipherUtils.getSupportedCiphers();
}

interface CipherArgs {
  isCipher: boolean;
  cipherType: string;
  cipherKey: BinaryLikeNode;
  iv: BinaryLike;
  options: Record<string, TransformOptions>;
}

class CipherCommon extends Stream.Transform {
  private native: NativeCipher;

  constructor({
    isCipher,
    cipherType,
    cipherKey,
    iv,
    options = {},
  }: CipherArgs) {
    super(options);
    this.native = NitroModules.createHybridObject<NativeCipher>('Cipher');
    const authTagLen: number =
      getUIntOption(options, 'authTagLength') !== -1
        ? getUIntOption(options, 'authTagLength')
        : 16; // defaults to 16 bytes
    this.native.setArgs({
      isCipher,
      cipherType,
      cipherKey: binaryLikeToArrayBuffer(cipherKey),
      iv: binaryLikeToArrayBuffer(iv),
      authTagLen,
    });
  }

  update(
    data: BinaryLike,
    inputEncoding?: Encoding,
    outputEncoding?: Encoding,
  ): Buffer | string {
    const defaultEncoding = getDefaultEncoding();
    inputEncoding = inputEncoding ?? defaultEncoding;
    outputEncoding = outputEncoding ?? defaultEncoding;

    if (typeof data === 'string') {
      validateEncoding(data, inputEncoding);
    } else if (!ArrayBuffer.isView(data)) {
      throw new Error('Invalid data argument');
    }

    const ret = this.native.update(
      binaryLikeToArrayBuffer(data, inputEncoding),
    );

    if (outputEncoding && outputEncoding !== 'buffer') {
      return ab2str(ret, outputEncoding);
    }

    return Buffer.from(ret);
  }

  final(): Buffer;
  final(outputEncoding: BufferEncoding | 'buffer'): string;
  final(outputEncoding?: BufferEncoding | 'buffer'): Buffer | string {
    const ret = this.native.final();

    if (outputEncoding && outputEncoding !== 'buffer') {
      return ab2str(ret, outputEncoding);
    }

    return Buffer.from(ret);
  }

  _transform(
    chunk: BinaryLike,
    encoding: BufferEncoding,
    callback: () => void,
  ) {
    this.push(this.update(chunk, normalizeEncoding(encoding)));
    callback();
  }

  _flush(callback: () => void) {
    this.push(this.final());
    callback();
  }

  public setAutoPadding(autoPadding?: boolean): this {
    const res = this.native.setAutoPadding(!!autoPadding);
    if (!res) {
      throw new Error('setAutoPadding failed');
    }
    return this;
  }

  public setAAD(
    buffer: Buffer,
    options?: {
      plaintextLength: number;
    },
  ): this {
    const res = this.native.setAAD(buffer.buffer, options?.plaintextLength);
    if (!res) {
      throw new Error('setAAD failed');
    }
    return this;
  }

  public getAuthTag(): Buffer {
    return Buffer.from(this.native.getAuthTag());
  }

  public setAuthTag(tag: Buffer): this {
    const res = this.native.setAuthTag(binaryLikeToArrayBuffer(tag));
    if (!res) {
      throw new Error('setAuthTag failed');
    }
    return this;
  }

  public getSupportedCiphers(): string[] {
    return this.native.getSupportedCiphers();
  }
}

class Cipheriv extends CipherCommon {
  constructor(
    cipherType: string,
    cipherKey: BinaryLikeNode,
    iv: BinaryLike,
    options: Record<string, TransformOptions> = {},
  ) {
    super({
      isCipher: true,
      cipherType,
      cipherKey: binaryLikeToArrayBuffer(cipherKey),
      iv: binaryLikeToArrayBuffer(iv),
      options,
    });
  }
}

type Cipher = Cipheriv;

class Decipheriv extends CipherCommon {
  constructor(
    cipherType: string,
    cipherKey: BinaryLikeNode,
    iv: BinaryLike,
    options: Record<string, TransformOptions> = {},
  ) {
    super({
      isCipher: false,
      cipherType,
      cipherKey: binaryLikeToArrayBuffer(cipherKey),
      iv: binaryLikeToArrayBuffer(iv),
      options,
    });
  }
}

type Decipher = Decipheriv;

export function createDecipheriv(
  algorithm: CipherCCMTypes,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options: CipherCCMOptions,
): Decipher;
export function createDecipheriv(
  algorithm: CipherOCBTypes,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options: CipherOCBOptions,
): Decipher;
export function createDecipheriv(
  algorithm: CipherGCMTypes,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options?: CipherGCMOptions,
): Decipher;
export function createDecipheriv(
  algorithm: string,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options?: Stream.TransformOptions,
): Decipher;
export function createDecipheriv(
  algorithm: string,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options?:
    | CipherCCMOptions
    | CipherOCBOptions
    | CipherGCMOptions
    | Stream.TransformOptions,
): Decipher {
  return new Decipheriv(
    algorithm,
    key,
    iv,
    options as Record<string, TransformOptions>,
  );
}

export function createCipheriv(
  algorithm: CipherCCMTypes,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options: CipherCCMOptions,
): Cipher;
export function createCipheriv(
  algorithm: CipherOCBTypes,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options: CipherOCBOptions,
): Cipher;
export function createCipheriv(
  algorithm: CipherGCMTypes,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options?: CipherGCMOptions,
): Cipher;
export function createCipheriv(
  algorithm: string,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options?: Stream.TransformOptions,
): Cipher;
export function createCipheriv(
  algorithm: string,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options?:
    | CipherCCMOptions
    | CipherOCBOptions
    | CipherGCMOptions
    | Stream.TransformOptions,
): Cipher {
  return new Cipheriv(
    algorithm,
    key,
    iv,
    options as Record<string, TransformOptions>,
  );
}

export const cipherExports = {
  createCipheriv,
  createDecipheriv,
  getCiphers,
};

export type { Cipher, Decipher };