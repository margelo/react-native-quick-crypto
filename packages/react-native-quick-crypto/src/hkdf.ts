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

// Output byte-length of each fixed-length digest. HKDF requires a fixed-
// output hash (it builds on HMAC), so XOFs like SHAKE128/256 are not
// included even though `normalizeHashName` will accept them — passing
// SHAKE here is a caller bug we surface as `Unsupported HKDF digest`
// instead of letting the native side return an opaque error.
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

function hkdfHashLen(digest: string): number {
  const hashLen = HKDF_HASH_BYTES[digest.toLowerCase()];
  if (hashLen === undefined) {
    throw new TypeError(`Unsupported HKDF digest: ${digest}`);
  }
  return hashLen;
}

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
  if (hashLen === undefined) {
    throw new TypeError(`Unsupported HKDF digest: ${digest}`);
  }
  // RFC 5869 §2.3: L ≤ 255 * HashLen.
  if (keylen > 255 * hashLen) {
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
        'full',
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
    'full',
  );

  return Buffer.from(result);
}

// RFC 5869 §2.2 HKDF-Extract (sync): PRK = HMAC(salt, IKM). Salt defaults to
// a string of HashLen zeros when omitted. Returns a PRK of HashLen bytes.
export function hkdfExtractSync(
  digest: string,
  ikm: KeyMaterial,
  salt: Salt = new Uint8Array(0),
): Buffer {
  const normalizedDigest = normalizeHashName(digest);
  const hashLen = hkdfHashLen(normalizedDigest);
  const sanitizedIkm = sanitizeInput(ikm, 'IKM');
  const sanitizedSalt = sanitizeInput(salt, 'Salt');

  const result = getNative().deriveKeySync(
    normalizedDigest,
    sanitizedIkm,
    sanitizedSalt,
    new ArrayBuffer(0),
    hashLen,
    'extract',
  );

  return Buffer.from(result);
}

// Async HKDF-Extract, mirroring `hkdf`. Unlike the sync form, `salt` is
// required here because the callback occupies the trailing argument.
export function hkdfExtract(
  digest: string,
  ikm: KeyMaterial,
  salt: Salt,
  callback: HkdfCallback,
): void {
  validateCallback(callback);

  try {
    const normalizedDigest = normalizeHashName(digest);
    const hashLen = hkdfHashLen(normalizedDigest);
    const sanitizedIkm = sanitizeInput(ikm, 'IKM');
    const sanitizedSalt = sanitizeInput(salt, 'Salt');

    getNative()
      .deriveKey(
        normalizedDigest,
        sanitizedIkm,
        sanitizedSalt,
        new ArrayBuffer(0),
        hashLen,
        'extract',
      )
      .then(
        res => callback(null, Buffer.from(res)),
        err => callback(err),
      );
  } catch (err) {
    callback(err as Error);
  }
}

// RFC 5869 §2.3 HKDF-Expand (sync): OKM = expand(PRK, info, L). `prk` must be
// at least HashLen bytes (a pseudorandom key, e.g. from hkdfExtract).
export function hkdfExpandSync(
  digest: string,
  prk: KeyMaterial,
  info: Info,
  keylen: number,
): Buffer {
  const normalizedDigest = normalizeHashName(digest);
  const hashLen = hkdfHashLen(normalizedDigest);
  const sanitizedPrk = sanitizeInput(prk, 'PRK');
  if (sanitizedPrk.byteLength < hashLen) {
    throw new RangeError(
      `HKDF-Expand PRK must be at least HashLen (${hashLen}) bytes for ${digest}`,
    );
  }
  const sanitizedInfo = sanitizeInput(info, 'Info');

  validateHkdfKeylen(normalizedDigest, keylen);

  const result = getNative().deriveKeySync(
    normalizedDigest,
    sanitizedPrk,
    new ArrayBuffer(0),
    sanitizedInfo,
    keylen,
    'expand',
  );

  return Buffer.from(result);
}

// Async HKDF-Expand, mirroring `hkdf`.
export function hkdfExpand(
  digest: string,
  prk: KeyMaterial,
  info: Info,
  keylen: number,
  callback: HkdfCallback,
): void {
  validateCallback(callback);

  try {
    const normalizedDigest = normalizeHashName(digest);
    const hashLen = hkdfHashLen(normalizedDigest);
    const sanitizedPrk = sanitizeInput(prk, 'PRK');
    if (sanitizedPrk.byteLength < hashLen) {
      throw new RangeError(
        `HKDF-Expand PRK must be at least HashLen (${hashLen}) bytes for ${digest}`,
      );
    }
    const sanitizedInfo = sanitizeInput(info, 'Info');

    validateHkdfKeylen(normalizedDigest, keylen);

    getNative()
      .deriveKey(
        normalizedDigest,
        sanitizedPrk,
        new ArrayBuffer(0),
        sanitizedInfo,
        keylen,
        'expand',
      )
      .then(
        res => callback(null, Buffer.from(res)),
        err => callback(err),
      );
  } catch (err) {
    callback(err as Error);
  }
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
    'full',
  );

  return result;
}
