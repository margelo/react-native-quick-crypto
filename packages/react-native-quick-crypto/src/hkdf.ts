import { Buffer } from '@craftzdog/react-native-buffer';
import { NitroModules } from 'react-native-nitro-modules';
import type { Hkdf as HkdfNative } from './specs/hkdf.nitro';
import { binaryLikeToArrayBuffer, normalizeHashName } from './utils';
import type { BinaryLike } from './utils';

type KeyMaterial = BinaryLike;
type Salt = BinaryLike;
type Info = BinaryLike;

export interface HkdfAlgorithm {
  name: string;
  hash: string | { name: string };
  salt: BinaryLike;
  info: BinaryLike;
}

export interface CryptoKeyInternal {
  keyObject: {
    export: () => Buffer;
  };
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

    if (keylen < 0) {
      throw new TypeError('Bad key length');
    }

    const nativeMod = getNative();
    // Nitro methods are synchronous unless async is specified, but to match Node.js callback style we can wrap or if we want true async offloading we'd need Promise support in Native.
    // The spec defined deriveKey as synchronous returning ArrayBuffer.
    // Node.js hkdf is async (updates in thread pool).
    // For now, we will execute synchronously and call callback.
    // If we wanted true async, we should have defined it as Promise in Nitro spec.
    // Given the task is to act like Node.js, and this is "Quick Crypto", we might want it to be fast.
    // However, crypto ops can be heavy.
    // Let's implement sync for now as per spec.

    const result = nativeMod.deriveKey(
      normalizedDigest,
      sanitizedKey,
      sanitizedSalt,
      sanitizedInfo,
      keylen,
    );

    callback(null, Buffer.from(result));
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

  if (keylen < 0) {
    throw new TypeError('Bad key length');
  }

  const nativeMod = getNative();
  const result = nativeMod.deriveKey(
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
  baseKey: CryptoKeyInternal,
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

  const nativeMod = getNative();
  const result = nativeMod.deriveKey(
    normalizedDigest,
    binaryLikeToArrayBuffer(keyBuffer),
    binaryLikeToArrayBuffer(salt),
    binaryLikeToArrayBuffer(info),
    keylen,
  );

  return result;
}
