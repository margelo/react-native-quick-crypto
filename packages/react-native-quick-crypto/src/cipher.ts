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
import { getDecoder, getDefaultEncoding, getUIntOption, normalizeEncoding, validateEncoding } from './utils/cipher';

class CipherCommon extends Stream.Transform {
  private native: NativeCipher;
  private decoder: StringDecoder | undefined;

  constructor(
    cipherType: string,
    cipherKey: BinaryLikeNode,
    isCipher: boolean,
    options: Record<string, TransformOptions> = {},
    iv: BinaryLike,
  ) {
    super(options);
    this.native = NitroModules.createHybridObject<NativeCipher>('Cipher');

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
    this.native = isCipher
      ? createInternalCipher(args)
      : createInternalDecipher(args);
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

  _transform(chunk: BinaryLike, encoding: BufferEncoding, callback: () => void) {
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
}

class Cipher extends CipherCommon {
  constructor(
    cipherType: string,
    cipherKey: BinaryLikeNode,
    options: Record<string, TransformOptions> = {},
    iv: BinaryLike,
  ) {
    iv = binaryLikeToArrayBuffer(iv);
    super(cipherType, cipherKey, true, options, iv);
  }
}

class Decipher extends CipherCommon {
  constructor(
    cipherType: string,
    cipherKey: BinaryLikeNode,
    options: Record<string, TransformOptions> = {},
    iv: BinaryLike,
  ) {
    iv = binaryLikeToArrayBuffer(iv);
    super(cipherType, cipherKey, false, options, iv);
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
): DecipherCCM | DecipherOCB | DecipherGCM | Decipher;
export function createDecipheriv(
  algorithm: string,
  key: BinaryLikeNode,
  iv: BinaryLike,
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
): CipherCCM | CipherOCB | CipherGCM | Cipher;
export function createCipheriv(
  algorithm: string,
  key: BinaryLikeNode,
  iv: BinaryLike,
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
