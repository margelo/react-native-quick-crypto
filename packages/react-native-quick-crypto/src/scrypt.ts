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

function getScryptParams(options?: ScryptOptions) {
  const N = options?.N ?? options?.cost ?? defaults.N;
  const r = options?.r ?? options?.blockSize ?? defaults.r;
  const p = options?.p ?? options?.parallelization ?? defaults.p;
  const maxmem = options?.maxmem ?? defaults.maxmem;

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

    if (keylen < 0) {
      throw new TypeError('Bad key length');
    }

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

  if (keylen < 0) {
    throw new TypeError('Bad key length');
  }

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
