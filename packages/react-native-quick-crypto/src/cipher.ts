import { NitroModules } from 'react-native-nitro-modules';
import Stream, { type TransformOptions } from 'readable-stream';
import { StringDecoder } from 'string_decoder';
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
import { binaryLikeToArrayBuffer } from './utils';
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
  name: string,
  options?: { keyLength?: number; ivLength?: number },
): CipherInfoResult | undefined {
  if (typeof name !== 'string' || name.length === 0) return undefined;
  return CipherUtils.getCipherInfo(name, options?.keyLength, options?.ivLength);
}

// libsodium ciphers aren't visible to OpenSSL's EVP_CIPHER_fetch, so
// getCipherInfo() returns undefined for them. Hard-code the (key, iv)
// byte-lengths the C++ factory will accept.
const LIBSODIUM_CIPHER_PARAMS: Readonly<
  Record<string, { keyLength: number; ivLength: number }>
> = {
  xsalsa20: { keyLength: 32, ivLength: 24 },
  'xsalsa20-poly1305': { keyLength: 32, ivLength: 24 },
  'xchacha20-poly1305': { keyLength: 32, ivLength: 24 },
};

function validateCipherParams(
  cipherType: string,
  keyByteLength: number,
  ivByteLength: number,
): void {
  if (typeof cipherType !== 'string' || cipherType.length === 0) {
    throw new TypeError('cipher algorithm must be a non-empty string');
  }
  // ArrayBuffer.byteLength is always a non-negative integer, so the only
  // out-of-range value we need to guard is 0 — empty key buffers must not
  // reach OpenSSL's EVP_CipherInit_ex.
  if (keyByteLength === 0) {
    throw new RangeError(`Invalid key length 0 for cipher ${cipherType}`);
  }

  const lower = cipherType.toLowerCase();
  const sodium = LIBSODIUM_CIPHER_PARAMS[lower];
  if (sodium) {
    // libsodium parlance: "nonce" rather than "iv". Phrase the expected
    // size as a natural-language clause so callers asserting on either
    // `key must be N bytes` or `Invalid key length N` both match.
    if (keyByteLength !== sodium.keyLength) {
      throw new RangeError(
        `Invalid key length ${keyByteLength} for cipher ${cipherType} ` +
          `(key must be ${sodium.keyLength} bytes)`,
      );
    }
    if (ivByteLength !== sodium.ivLength) {
      throw new RangeError(
        `Invalid nonce length ${ivByteLength} for cipher ${cipherType} ` +
          `(nonce must be ${sodium.ivLength} bytes)`,
      );
    }
    return;
  }

  // OpenSSL path. Look up the cipher's defaults once. Most callers pass
  // exactly the cipher's default key/iv lengths (e.g. AES-128-CBC always
  // wants 16/16) — short-circuit those to a single native round-trip.
  // Variable-length ciphers (GCM, CCM, OCB, ChaCha20-Poly1305) fall through
  // to per-parameter validation calls so the error message can name which
  // of {key, iv} is wrong.
  const info = CipherUtils.getCipherInfo(cipherType);
  if (info === undefined) {
    throw new TypeError(`Unsupported or unknown cipher type: ${cipherType}`);
  }

  const expectedIv = info.ivLength ?? 0;
  if (expectedIv === 0 && ivByteLength > 0) {
    throw new RangeError(
      `Cipher ${cipherType} does not use an iv (got ${ivByteLength} bytes)`,
    );
  }
  if (expectedIv > 0 && ivByteLength === 0) {
    throw new RangeError(
      `Cipher ${cipherType} requires an iv but none was provided`,
    );
  }

  // Fast path: lengths match the cipher's defaults exactly.
  if (info.keyLength === keyByteLength && expectedIv === ivByteLength) {
    return;
  }

  // Variable-length: verify against native one parameter at a time.
  if (
    CipherUtils.getCipherInfo(cipherType, keyByteLength, undefined) ===
    undefined
  ) {
    throw new RangeError(
      `Invalid key length ${keyByteLength} for cipher ${cipherType}`,
    );
  }
  if (
    expectedIv > 0 &&
    CipherUtils.getCipherInfo(cipherType, undefined, ivByteLength) === undefined
  ) {
    throw new RangeError(
      `Invalid iv length ${ivByteLength} for cipher ${cipherType}`,
    );
  }
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
  private _decoder: StringDecoder | null = null;
  private _decoderEncoding: string | undefined = undefined;

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

    // defaults to 16 bytes for AEAD modes; non-AEAD callers ignore it.
    const authTagLen =
      getUIntOption(
        options as Readonly<Record<string, unknown>> | undefined,
        'authTagLength',
      ) ?? 16;

    const cipherKeyAB = binaryLikeToArrayBuffer(cipherKey);
    const ivAB = binaryLikeToArrayBuffer(iv);
    validateCipherParams(cipherType, cipherKeyAB.byteLength, ivAB.byteLength);

    const factory =
      NitroModules.createHybridObject<CipherFactory>('CipherFactory');
    this.native = factory.createCipher({
      isCipher,
      cipherType,
      cipherKey: cipherKeyAB,
      iv: ivAB,
      authTagLen,
    });
  }

  private getDecoder(encoding: string): StringDecoder {
    const normalized = normalizeEncoding(encoding);
    if (!this._decoder) {
      this._decoder = new StringDecoder(encoding as BufferEncoding);
      this._decoderEncoding = normalized;
    } else if (this._decoderEncoding !== normalized) {
      throw new Error('Cannot change encoding');
    }
    return this._decoder;
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
      return this.getDecoder(outputEncoding).write(Buffer.from(ret));
    }

    return Buffer.from(ret);
  }

  final(): Buffer;
  final(outputEncoding: BufferEncoding | 'buffer'): string;
  final(outputEncoding?: BufferEncoding | 'buffer'): Buffer | string {
    const ret = this.native.final();

    if (outputEncoding && outputEncoding !== 'buffer') {
      return this.getDecoder(outputEncoding).end(Buffer.from(ret));
    }

    return Buffer.from(ret);
  }

  // Stream interface — surface synchronous errors (bad encoding,
  // OpenSSL EVP failures, AEAD tag mismatch in `final()`, etc.) via
  // the callback so they emit as stream 'error' events instead of
  // throwing out of the Transform plumbing and crashing the host
  // pipeline.
  _transform(
    chunk: BinaryLike,
    encoding: BufferEncoding,
    callback: (err?: Error | null) => void,
  ) {
    try {
      this.push(this.update(chunk, normalizeEncoding(encoding)));
      callback();
    } catch (err) {
      callback(err as Error);
    }
  }

  _flush(callback: (err?: Error | null) => void) {
    try {
      this.push(this.final());
      callback();
    } catch (err) {
      callback(err as Error);
    }
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
    // Use binaryLikeToArrayBuffer (not `buffer.buffer`) so that sliced /
    // offset views send only the AAD bytes the caller intended. Passing the
    // raw backing ArrayBuffer authenticates the wrong data and silently
    // breaks the AEAD integrity guarantee.
    const res = this.native.setAAD(
      binaryLikeToArrayBuffer(buffer),
      options?.plaintextLength,
    );
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
  const cipherKeyAB = binaryLikeToArrayBuffer(key);
  const ivAB = binaryLikeToArrayBuffer(nonce);
  validateCipherParams('xsalsa20', cipherKeyAB.byteLength, ivAB.byteLength);

  const factory =
    NitroModules.createHybridObject<CipherFactory>('CipherFactory');
  const native = factory.createCipher({
    isCipher: true,
    cipherType: 'xsalsa20',
    cipherKey: cipherKeyAB,
    iv: ivAB,
  });
  const result = native.update(binaryLikeToArrayBuffer(data));
  return new Uint8Array(result);
}
