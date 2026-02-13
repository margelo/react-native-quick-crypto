import { NitroModules } from 'react-native-nitro-modules';
import Stream, { type TransformOptions } from 'readable-stream';
import { Buffer } from '@craftzdog/react-native-buffer';
import type { BinaryLike, BinaryLikeNode, Encoding } from './utils';
import type {
  CipherCCMOptions,
  CipherCCMTypes,
  CipherGCMTypes,
  CipherGCMOptions,
  CipherOCBOptions,
  CipherOCBTypes,
} from 'crypto'; // @types/node
import type {
  Cipher as NativeCipher,
  CipherFactory,
} from './specs/cipher.nitro';
import { ab2str, binaryLikeToArrayBuffer } from './utils';
import {
  getDefaultEncoding,
  getUIntOption,
  normalizeEncoding,
  validateEncoding,
} from './utils/cipher';

export type CipherOptions =
  | CipherCCMOptions
  | CipherOCBOptions
  | CipherGCMOptions
  | TransformOptions;

export interface CipherInfoResult {
  name: string;
  nid: number;
  mode: string;
  keyLength: number;
  blockSize?: number;
  ivLength?: number;
}

class CipherUtils {
  private static native =
    NitroModules.createHybridObject<NativeCipher>('Cipher');
  public static getSupportedCiphers(): string[] {
    return this.native.getSupportedCiphers();
  }
  public static getCipherInfo(
    name: string,
    keyLength?: number,
    ivLength?: number,
  ): CipherInfoResult | undefined {
    return this.native.getCipherInfo(name, keyLength, ivLength);
  }
}

export function getCiphers(): string[] {
  return CipherUtils.getSupportedCiphers();
}

export function getCipherInfo(
  nameOrNid: string | number,
  options?: { keyLength?: number; ivLength?: number },
): CipherInfoResult | undefined {
  if (typeof nameOrNid === 'string') {
    if (nameOrNid.length === 0) return undefined;
    return CipherUtils.getCipherInfo(
      nameOrNid,
      options?.keyLength,
      options?.ivLength,
    );
  }
  throw new TypeError('nameOrNid must be a string');
}

interface CipherArgs {
  isCipher: boolean;
  cipherType: string;
  cipherKey: BinaryLikeNode;
  iv: BinaryLike;
  options?: CipherOptions;
}

class CipherCommon extends Stream.Transform {
  private native: NativeCipher;

  constructor({ isCipher, cipherType, cipherKey, iv, options }: CipherArgs) {
    // Explicitly create TransformOptions for super()
    const streamOptions: TransformOptions = {};
    if (options) {
      // List known TransformOptions keys (adjust if needed)
      const transformKeys: Array<keyof TransformOptions> = [
        'readableHighWaterMark',
        'writableHighWaterMark',
        'decodeStrings',
        'defaultEncoding',
        'objectMode',
        'destroy',
        'read',
        'write',
        'writev',
        'final',
        'transform',
        'flush',
        // Add any other relevant keys from readable-stream's TransformOptions
      ];
      for (const key of transformKeys) {
        if (key in options) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (streamOptions as any)[key] = (options as any)[key];
        }
      }
    }
    super(streamOptions); // Pass filtered options

    const authTagLen: number =
      getUIntOption(options ?? {}, 'authTagLength') !== -1
        ? getUIntOption(options ?? {}, 'authTagLength')
        : 16; // defaults to 16 bytes

    const factory =
      NitroModules.createHybridObject<CipherFactory>('CipherFactory');
    this.native = factory.createCipher({
      isCipher,
      cipherType,
      cipherKey: binaryLikeToArrayBuffer(cipherKey),
      iv: binaryLikeToArrayBuffer(iv),
      authTagLen,
    });
  }

  update(data: Buffer): Buffer;
  update(data: BinaryLike, inputEncoding?: Encoding): Buffer;
  update(
    data: BinaryLike,
    inputEncoding: Encoding,
    outputEncoding: Encoding,
  ): string;
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
    // Check if native parts are initialized
    if (!this.native || typeof this.native.setAAD !== 'function') {
      throw new Error('Cipher native object or setAAD method not initialized.');
    }
    const res = this.native.setAAD(buffer.buffer, options?.plaintextLength);
    if (!res) {
      throw new Error('setAAD failed (native call returned false)');
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
    options?: CipherOptions,
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

export type Cipher = Cipheriv;

class Decipheriv extends CipherCommon {
  constructor(
    cipherType: string,
    cipherKey: BinaryLikeNode,
    iv: BinaryLike,
    options?: CipherOptions,
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

export type Decipher = Decipheriv;

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
  options?: TransformOptions,
): Decipher;
export function createDecipheriv(
  algorithm: string,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options?: CipherOptions,
): Decipher {
  return new Decipheriv(algorithm, key, iv, options);
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
  options?: TransformOptions,
): Cipher;
export function createCipheriv(
  algorithm: string,
  key: BinaryLikeNode,
  iv: BinaryLike,
  options?: CipherOptions,
): Cipher {
  return new Cipheriv(algorithm, key, iv, options);
}

/**
 * xsalsa20 stream encryption with @noble/ciphers compatible API
 *
 * @param key - 32 bytes
 * @param nonce - 24 bytes
 * @param data - data to encrypt
 * @param output - unused
 * @param counter - unused
 * @returns encrypted data
 */
export function xsalsa20(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  // @ts-expect-error haven't implemented this part of @noble/ciphers API
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  output?: Uint8Array | undefined,
  // @ts-expect-error haven't implemented this part of @noble/ciphers API
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  counter?: number,
): Uint8Array {
  const factory =
    NitroModules.createHybridObject<CipherFactory>('CipherFactory');
  const native = factory.createCipher({
    isCipher: true,
    cipherType: 'xsalsa20',
    cipherKey: binaryLikeToArrayBuffer(key),
    iv: binaryLikeToArrayBuffer(nonce),
  });
  const result = native.update(binaryLikeToArrayBuffer(data));
  return new Uint8Array(result);
}
