import { Buffer } from '@craftzdog/react-native-buffer';
import { NitroModules } from 'react-native-nitro-modules';
import type { Scrypt as NativeScrypt } from './specs/scrypt.nitro';
import { binaryLikeToArrayBuffer } from './utils';
import type { BinaryLike } from './utils';

type Password = BinaryLike;
type Salt = BinaryLike;

export interface ScryptOptions {
  N?: number;
  r?: number;
  p?: number;
  cost?: number;
  blockSize?: number;
  parallelization?: number;
  maxmem?: number;
}

type ScryptCallback = (err: Error | null, derivedKey?: Buffer) => void;

// Lazy load native module
let native: NativeScrypt;
function getNative(): NativeScrypt {
  if (native == null) {
    native = NitroModules.createHybridObject<NativeScrypt>('Scrypt');
  }
  return native;
}

const defaults = {
  N: 16384,
  r: 8,
  p: 1,
  maxmem: 32 * 1024 * 1024,
};

// RFC 7914 § 2: scrypt parameters
//   N — CPU/memory cost; must be a power of 2 > 1.
//   r — block size; positive integer.
//   p — parallelization factor; positive integer.
//   r * p must be < 2^30 (otherwise the spec output is undefined).
//   The work buffer is 128 * r * N bytes, which must fit in maxmem.
const SCRYPT_MAX_RP = 1 << 30; // 2^30 per RFC 7914

function isPositiveInteger(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isFinite(value) &&
    Number.isInteger(value) &&
    value > 0
  );
}

function validateScryptParams(
  N: number,
  r: number,
  p: number,
  maxmem: number,
): void {
  if (!isPositiveInteger(N)) {
    throw new RangeError(`Invalid scrypt cost (N): ${N}`);
  }
  // Power-of-two & > 1 check (RFC 7914 §6 step 1).
  if (N <= 1 || (N & (N - 1)) !== 0) {
    throw new RangeError(
      `Invalid scrypt cost (N): ${N} — must be a power of 2 greater than 1`,
    );
  }
  if (!isPositiveInteger(r)) {
    throw new RangeError(`Invalid scrypt blockSize (r): ${r}`);
  }
  if (!isPositiveInteger(p)) {
    throw new RangeError(`Invalid scrypt parallelization (p): ${p}`);
  }
  if (r * p >= SCRYPT_MAX_RP) {
    throw new RangeError(
      `Invalid scrypt parameters: r * p (${r * p}) must be < 2^30`,
    );
  }
  if (!isPositiveInteger(maxmem)) {
    throw new RangeError(`Invalid scrypt maxmem: ${maxmem}`);
  }
  // 128 * r * N is the minimum working memory. Reject early so we don't
  // hand a doomed parameter set to native and OOM the device.
  const required = 128 * r * N;
  if (required > maxmem) {
    throw new RangeError(
      `Invalid scrypt parameters: working memory ${required} bytes ` +
        `exceeds maxmem ${maxmem}`,
    );
  }
}

function validateScryptKeylen(keylen: number): void {
  if (
    typeof keylen !== 'number' ||
    !Number.isFinite(keylen) ||
    !Number.isInteger(keylen) ||
    keylen < 0 ||
    keylen > 0x7fff_ffff
  ) {
    throw new TypeError('Bad key length');
  }
}

function getScryptParams(options?: ScryptOptions) {
  const N = options?.N ?? options?.cost ?? defaults.N;
  const r = options?.r ?? options?.blockSize ?? defaults.r;
  const p = options?.p ?? options?.parallelization ?? defaults.p;
  const maxmem = options?.maxmem ?? defaults.maxmem;

  validateScryptParams(N, r, p, maxmem);

  return { N, r, p, maxmem };
}

function validateCallback(callback: ScryptCallback) {
  if (callback === undefined || typeof callback !== 'function') {
    throw new Error('No callback provided to scrypt');
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

export function scrypt(
  password: Password,
  salt: Salt,
  keylen: number,
  options?: ScryptOptions | ScryptCallback,
  callback?: ScryptCallback,
): void {
  let cb: ScryptCallback;
  let opts: ScryptOptions | undefined;

  if (typeof options === 'function') {
    cb = options;
    opts = undefined;
  } else {
    cb = callback!;
    opts = options;
  }

  validateCallback(cb);

  try {
    const { N, r, p, maxmem } = getScryptParams(opts);
    const sanitizedPassword = sanitizeInput(password, 'Password');
    const sanitizedSalt = sanitizeInput(salt, 'Salt');

    validateScryptKeylen(keylen);

    const nativeMod = getNative();
    nativeMod
      .deriveKey(sanitizedPassword, sanitizedSalt, N, r, p, maxmem, keylen)
      .then(
        res => {
          cb(null, Buffer.from(res));
        },
        err => {
          cb(err);
        },
      );
  } catch (err) {
    cb(err as Error);
  }
}

export function scryptSync(
  password: Password,
  salt: Salt,
  keylen: number,
  options?: ScryptOptions,
): Buffer {
  const { N, r, p, maxmem } = getScryptParams(options);
  const sanitizedPassword = sanitizeInput(password, 'Password');
  const sanitizedSalt = sanitizeInput(salt, 'Salt');

  validateScryptKeylen(keylen);

  const nativeMod = getNative();
  const result = nativeMod.deriveKeySync(
    sanitizedPassword,
    sanitizedSalt,
    N,
    r,
    p,
    maxmem,
    keylen,
  );

  return Buffer.from(result);
}
