import { Buffer } from '@craftzdog/react-native-buffer';
import { NitroModules } from 'react-native-nitro-modules';
import type { Hkdf as HkdfNative } from './specs/hkdf.nitro';
import { binaryLikeToArrayBuffer, normalizeHashName } from './utils';
import type { BinaryLike } from './utils';
import type { CryptoKey } from './keys';

type KeyMaterial = BinaryLike;
type Salt = BinaryLike;
type Info = BinaryLike;

export interface HkdfAlgorithm {
  name: string;
  hash: string | { name: string };
  salt: BinaryLike;
  info: BinaryLike;
}

export interface HkdfCallback {
  (err: Error | null, derivedKey?: Buffer): void;
}

// Lazy load native module
let native: HkdfNative;
function getNative(): HkdfNative {
  if (native == null) {
    native = NitroModules.createHybridObject<HkdfNative>('Hkdf');
  }
  return native;
}

function validateCallback(callback: HkdfCallback) {
  if (callback === undefined || typeof callback !== 'function') {
    throw new Error('No callback provided to hkdf');
  }
}

function sanitizeInput(input: BinaryLike, name: string): ArrayBuffer {
  try {
    return binaryLikeToArrayBuffer(input);
  } catch {
    throw new Error(
      `${name} must be a string, a Buffer, a typed array, or a DataView`,
    );
  }
}

// Output byte-length of each digest the C++ Hkdf supports. Used to enforce
// the RFC 5869 §2.3 ceiling: L ≤ 255 * HashLen.
const HKDF_HASH_BYTES: Readonly<Record<string, number>> = {
  sha1: 20,
  sha224: 28,
  sha256: 32,
  sha384: 48,
  sha512: 64,
  'sha3-256': 32,
  'sha3-384': 48,
  'sha3-512': 64,
  ripemd160: 20,
};

function validateHkdfKeylen(digest: string, keylen: number): void {
  if (
    typeof keylen !== 'number' ||
    !Number.isFinite(keylen) ||
    !Number.isInteger(keylen) ||
    keylen < 0 ||
    keylen > 0x7fff_ffff
  ) {
    throw new TypeError('Bad key length');
  }
  const hashLen = HKDF_HASH_BYTES[digest.toLowerCase()];
  if (hashLen !== undefined && keylen > 255 * hashLen) {
    throw new RangeError(
      `HKDF keylen ${keylen} exceeds RFC 5869 ceiling ` +
        `255 * HashLen (${255 * hashLen}) for ${digest}`,
    );
  }
}

export function hkdf(
  digest: string,
  key: KeyMaterial,
  salt: Salt,
  info: Info,
  keylen: number,
  callback: HkdfCallback,
): void {
  validateCallback(callback);

  try {
    const normalizedDigest = normalizeHashName(digest);
    const sanitizedKey = sanitizeInput(key, 'Key');
    const sanitizedSalt = sanitizeInput(salt, 'Salt');
    const sanitizedInfo = sanitizeInput(info, 'Info');

    validateHkdfKeylen(normalizedDigest, keylen);

    const nativeMod = getNative();
    nativeMod
      .deriveKey(
        normalizedDigest,
        sanitizedKey,
        sanitizedSalt,
        sanitizedInfo,
        keylen,
      )
      .then(
        res => {
          callback(null, Buffer.from(res));
        },
        err => {
          callback(err);
        },
      );
  } catch (err) {
    callback(err as Error);
  }
}

export function hkdfSync(
  digest: string,
  key: KeyMaterial,
  salt: Salt,
  info: Info,
  keylen: number,
): Buffer {
  const normalizedDigest = normalizeHashName(digest);
  const sanitizedKey = sanitizeInput(key, 'Key');
  const sanitizedSalt = sanitizeInput(salt, 'Salt');
  const sanitizedInfo = sanitizeInput(info, 'Info');

  validateHkdfKeylen(normalizedDigest, keylen);

  const nativeMod = getNative();
  const result = nativeMod.deriveKeySync(
    normalizedDigest,
    sanitizedKey,
    sanitizedSalt,
    sanitizedInfo,
    keylen,
  );

  return Buffer.from(result);
}

export function hkdfDeriveBits(
  algorithm: HkdfAlgorithm,
  baseKey: CryptoKey,
  length: number,
): ArrayBuffer {
  const hash = algorithm.hash;
  const salt = algorithm.salt;
  const info = algorithm.info;

  // Check if key is extractable or we can access its handle/buffer
  // For raw keys, we can export.
  const keyBuffer = baseKey.keyObject.export();

  // length is in bits, native expects bytes
  const keylen = Math.ceil(length / 8);

  const hashName = typeof hash === 'string' ? hash : hash.name;
  const normalizedDigest = normalizeHashName(hashName);

  validateHkdfKeylen(normalizedDigest, keylen);

  const nativeMod = getNative();
  const result = nativeMod.deriveKeySync(
    normalizedDigest,
    binaryLikeToArrayBuffer(keyBuffer),
    binaryLikeToArrayBuffer(salt),
    binaryLikeToArrayBuffer(info),
    keylen,
  );

  return result;
}
