import { NitroModules } from 'react-native-nitro-modules';
import Stream, { type TransformOptions } from 'readable-stream';
import { StringDecoder } from 'string_decoder';
import { Buffer } from '@craftzdog/react-native-buffer';
import { Buffer as SBuffer } from 'safe-buffer';
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
import type { Cipher as NativeCipher } from './specs/cipher.nitro';
import { binaryLikeToArrayBuffer } from './utils';
import type { BinaryLike, BinaryLikeNode, CipherType, Encoding } from './utils';
import {
  getDecoder,
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
  private decoder: StringDecoder | undefined;

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
  ): ArrayBuffer | string {
    const defaultEncoding = getDefaultEncoding();
    inputEncoding = inputEncoding ?? defaultEncoding;
    outputEncoding = outputEncoding ?? defaultEncoding;

    if (typeof data === 'string') {
      validateEncoding(data, inputEncoding);
    } else if (!ArrayBuffer.isView(data)) {
      throw new Error('Invalid data argument');
    }

    data = binaryLikeToArrayBuffer(data, inputEncoding);
    const ret = this.native.update(data);

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
    const ret = this.native.final();

    if (outputEncoding && outputEncoding !== 'buffer') {
      this.decoder = getDecoder(this.decoder, outputEncoding);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return this.decoder!.end(SBuffer.from(ret) as any);
    }

    return ret;
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
  iv: BinaryLike,
  options?: Stream.TransformOptions,
): DecipherCCM | DecipherOCB | DecipherGCM | Decipheriv;
export function createDecipheriv(
  algorithm: string,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options?:
    | CipherCCMOptions
    | CipherOCBOptions
    | CipherGCMOptions
    | Stream.TransformOptions,
): DecipherCCM | DecipherOCB | DecipherGCM | Decipheriv {
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
  iv: BinaryLike,
  options?: Stream.TransformOptions,
): CipherCCM | CipherOCB | CipherGCM | Cipheriv;
export function createCipheriv(
  algorithm: string,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options?:
    | CipherCCMOptions
    | CipherOCBOptions
    | CipherGCMOptions
    | Stream.TransformOptions,
): CipherCCM | CipherOCB | CipherGCM | Cipheriv {
  return new Cipheriv(
    algorithm,
    key,
    iv,
    options as Record<string, TransformOptions>,
  );
}
