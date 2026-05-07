import { Buffer } from '@craftzdog/react-native-buffer';
import type { ABV, RandomCallback } from './utils';
import {
  abvToArrayBuffer,
  lazyDOMException,
  QuotaExceededError,
  rejectSharedArrayBuffer,
} from './utils';
import { NitroModules } from 'react-native-nitro-modules';
import type { Random } from './specs/random.nitro';

// to use native bits in sub-functions, use getNative(). don't call it at top-level!
let random: Random;
function getNative(): Random {
  if (random == null) {
    // lazy-load the Nitro HybridObject
    random = NitroModules.createHybridObject<Random>('Random');
  }
  return random;
}

export function randomFill<T extends ABV>(
  buffer: T,
  callback: RandomCallback<T>,
): void;

export function randomFill<T extends ABV>(
  buffer: T,
  offset: number,
  callback: RandomCallback<T>,
): void;

export function randomFill<T extends ABV>(
  buffer: T,
  offset: number,
  size: number,
  callback: RandomCallback<T>,
): void;

export function randomFill(buffer: ABV, ...rest: unknown[]): void {
  if (typeof rest[rest.length - 1] !== 'function') {
    throw new Error('No callback provided to randomFill');
  }

  const callback = rest[rest.length - 1] as unknown as (
    err: Error | null,
    buf?: ArrayBuffer,
  ) => void;

  const viewOffset = ArrayBuffer.isView(buffer) ? buffer.byteOffset : 0;
  const viewLength = buffer.byteLength;

  let offset: number = 0;
  let size: number = viewLength;

  if (typeof rest[2] === 'function') {
    offset = rest[0] as number;
    size = rest[1] as number;
  }

  if (typeof rest[1] === 'function') {
    offset = rest[0] as number;
    size = viewLength - offset;
  }

  getNative();
  const ab = abvToArrayBuffer(buffer);
  const start = viewOffset + offset;
  random.randomFill(ab, start, size).then(
    (res: ArrayBuffer) => {
      // The native async path operates on a copy of the underlying buffer to
      // avoid races with JS-owned memory on the worker thread, so the
      // randomized bytes live in `res`, not in the caller's buffer. Copy them
      // back to preserve Node's in-place randomFill semantics.
      if (res !== ab) {
        new Uint8Array(ab, start, size).set(new Uint8Array(res, start, size));
      }
      callback(null, res);
    },
    (e: Error) => {
      callback(e);
    },
  );
}

export function randomFillSync<T extends ABV>(
  buffer: T,
  offset?: number,
  size?: number,
): T;

export function randomFillSync(buffer: ABV, offset: number = 0, size?: number) {
  getNative();
  const viewOffset = ArrayBuffer.isView(buffer) ? buffer.byteOffset : 0;
  const viewLength = buffer.byteLength;
  const arrayBuffer = abvToArrayBuffer(buffer);
  random.randomFillSync(
    arrayBuffer,
    viewOffset + offset,
    size ?? viewLength - offset,
  );
  return buffer;
}

export function randomBytes(size: number): Buffer;

export function randomBytes(
  size: number,
  callback: (err: Error | null, buf?: Buffer) => void,
): void;

export function randomBytes(
  size: number,
  callback?: (err: Error | null, buf?: Buffer) => void,
): void | Buffer {
  const buf = new Buffer(size);

  if (callback === undefined) {
    randomFillSync(buf.buffer, 0, size);
    return buf;
  }

  randomFill(buf.buffer, 0, size, (error: Error | null, res: ArrayBuffer) => {
    if (error) {
      callback(error);
    }
    callback(null, Buffer.from(res));
  });
}

export const rng = randomBytes;
export const pseudoRandomBytes = randomBytes;
export const prng = randomBytes;

type RandomIntCallback = (err: Error | null, value: number) => void;
type Task = {
  min: number;
  max: number;
  callback: RandomIntCallback;
};

// The rest of the file is taken from https://github.com/nodejs/node/blob/master/lib/internal/crypto/random.js

// Largest integer we can read from a buffer.
// e.g.: Buffer.from("ff".repeat(6), "hex").readUIntBE(0, 6);
const RAND_MAX = 0xffffffffffff;

// Cache random data to use in randomInt. The cache size must be evenly
// divisible by 6 because each attempt to obtain a random int uses 6 bytes.
let randomCache = new Buffer(6 * 1024);
let randomCacheOffset = randomCache.length;
let asyncCacheFillInProgress = false;
const asyncCachePendingTasks: Task[] = [];

// Generates an integer in [min, max) range where min is inclusive and max is
// exclusive.

export function randomInt(max: number, callback: RandomIntCallback): void;
export function randomInt(max: number): number;
export function randomInt(
  min: number,
  max: number,
  callback: RandomIntCallback,
): void;
export function randomInt(min: number, max: number): number;
export function randomInt(
  arg1: number,
  arg2?: number | RandomIntCallback,
  callback?: RandomIntCallback,
): void | number {
  // Detect optional min syntax
  // randomInt(max)
  // randomInt(max, callback)
  let max: number;
  let min: number;
  const minNotSpecified =
    typeof arg2 === 'undefined' || typeof arg2 === 'function';

  if (minNotSpecified) {
    callback = arg2 as undefined | RandomIntCallback;
    max = arg1;
    min = 0;
  } else {
    min = arg1;
    max = arg2 as number;
  }
  if (typeof callback !== 'undefined' && typeof callback !== 'function') {
    throw new TypeError('callback must be a function or undefined');
  }

  const isSync = typeof callback === 'undefined';
  if (!Number.isSafeInteger(min)) {
    // todo throw new ERR_INVALID_ARG_TYPE('min', 'a safe integer', min);
    throw 'ERR_INVALID_ARG_TYPE';
  }
  if (!Number.isSafeInteger(max)) {
    // todo throw new ERR_INVALID_ARG_TYPE('max', 'a safe integer', max);
    throw 'ERR_INVALID_ARG_TYPE';
  }
  if (max <= min) {
    /* todo throw new ERR_OUT_OF_RANGE(
      'max',
      `greater than the value of "min" (${min})`,
      max
    );*/
    throw 'ERR_OUT_OF_RANGE';
  }

  // First we generate a random int between [0..range)
  const range = max - min;

  if (!(range <= RAND_MAX)) {
    /* todo throw new ERR_OUT_OF_RANGE(
      `max${minNotSpecified ? '' : ' - min'}`,
      `<= ${RAND_MAX}`,
      range
    );*/
    throw 'ERR_OUT_OF_RANGE';
  }

  // For (x % range) to produce an unbiased value greater than or equal to 0 and
  // less than range, x must be drawn randomly from the set of integers greater
  // than or equal to 0 and less than randLimit.
  const randLimit = RAND_MAX - (RAND_MAX % range);

  // If we don't have a callback, or if there is still data in the cache, we can
  // do this synchronously, which is super fast.
  while (isSync || randomCacheOffset < randomCache.length) {
    if (randomCacheOffset === randomCache.length) {
      // This might block the thread for a bit, but we are in sync mode.
      randomFillSync(randomCache);
      randomCacheOffset = 0;
    }

    const x = randomCache.readUIntBE(randomCacheOffset, 6);
    randomCacheOffset += 6;

    if (x < randLimit) {
      const n = (x % range) + min;
      if (isSync) return n;
      process.nextTick(callback as RandomIntCallback, null, n);
      return;
    }
  }

  // At this point, we are in async mode with no data in the cache. We cannot
  // simply refill the cache, because another async call to randomInt might
  // already be doing that. Instead, queue this call for when the cache has
  // been refilled.
  if (callback !== undefined) {
    // it is (typescript doesn't know it)
    asyncCachePendingTasks.push({ min, max, callback });
    asyncRefillRandomIntCache();
  }
}

function asyncRefillRandomIntCache() {
  if (asyncCacheFillInProgress) return;

  asyncCacheFillInProgress = true;
  randomFill(randomCache, (err, res) => {
    asyncCacheFillInProgress = false;

    const tasks = asyncCachePendingTasks;
    const errorReceiver = err && tasks.shift();
    if (!err) {
      randomCache = Buffer.from(res);
      randomCacheOffset = 0;
    }

    // Restart all pending tasks. If an error occurred, we only notify a single
    // callback (errorReceiver) about it. This way, every async call to
    // randomInt has a chance of being successful, and it avoids complex
    // exception handling here.
    tasks.splice(0).forEach(task => {
      randomInt(task.min, task.max, task.callback);
    });

    // This is the only call that might throw, and is therefore done at the end.
    if (errorReceiver) errorReceiver.callback(err, 0);
  });
}

// to require('crypto').randomFillSync() with an
// additional limitation that the input buffer is
// not allowed to exceed 65536 bytes, and can only
// be an integer-type TypedArray.
export type RandomTypedArrays =
  | Int8Array
  | Int16Array
  | Int32Array
  | Uint8Array
  | Uint16Array
  | Uint32Array;

// WebCrypto §getRandomValues only accepts integer-typed views. Float and
// non-TypedArray ABVs (DataView) must be rejected with a TypeMismatchError
// DOMException — see https://w3c.github.io/webcrypto/#Crypto-method-getRandomValues
const INTEGER_TYPED_ARRAY_TAGS = new Set([
  'Int8Array',
  'Int16Array',
  'Int32Array',
  'Uint8Array',
  'Uint8ClampedArray',
  'Uint16Array',
  'Uint32Array',
  'BigInt64Array',
  'BigUint64Array',
]);

function isIntegerTypedArray(value: unknown): boolean {
  if (!ArrayBuffer.isView(value)) return false;
  const tag = (value as { [Symbol.toStringTag]?: string })[Symbol.toStringTag];
  return tag !== undefined && INTEGER_TYPED_ARRAY_TAGS.has(tag);
}

/**
 * Fills the provided typed array with cryptographically strong random values.
 *
 * @param data The data to fill with random values
 * @returns The filled data
 */
export function getRandomValues(data: RandomTypedArrays) {
  // WebIDL BufferSource conversion (TypeError) must run before the
  // WebCrypto-specific integer-type / size checks (TypeMismatchError /
  // QuotaExceededError). `randomFillSync` below also rejects SAB via
  // `abvToArrayBuffer`, but by then we'd already have thrown the wrong
  // error type for a non-integer SAB-view, so the explicit early call is
  // load-bearing for spec compliance — not redundant.
  rejectSharedArrayBuffer(data);
  if (!isIntegerTypedArray(data)) {
    throw lazyDOMException(
      'The data argument must be an integer-type TypedArray',
      'TypeMismatchError',
    );
  }
  if (data.byteLength > 65536) {
    throw new QuotaExceededError('The requested length exceeds 65,536 bytes', {
      quota: 65536,
      requested: data.byteLength,
    });
  }
  randomFillSync(data, 0);
  return data;
}

const byteToHex: string[] = [];

for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 0x100).toString(16).slice(1));
}

export interface RandomUUIDOptions {
  // Accepted for Node.js parity. RNQC does not buffer entropy, so this is a
  // no-op: every UUID already pulls fresh bytes from the OS CSPRNG.
  disableEntropyCache?: boolean;
}

function validateRandomUUIDOptions(options?: RandomUUIDOptions): void {
  if (options === undefined) return;
  if (typeof options !== 'object' || options === null) {
    throw new TypeError('options must be an object');
  }
  if (
    options.disableEntropyCache !== undefined &&
    typeof options.disableEntropyCache !== 'boolean'
  ) {
    throw new TypeError('options.disableEntropyCache must be a boolean');
  }
}

// RFC 9562 variant 10xx is shared by v4 and v7.
function serializeUUID(buffer: Buffer, version: number): string {
  buffer[6] = (buffer[6]! & 0x0f) | (version << 4);
  buffer[8] = (buffer[8]! & 0x3f) | 0x80;

  return (
    byteToHex[buffer[0]!]! +
    byteToHex[buffer[1]!] +
    byteToHex[buffer[2]!] +
    byteToHex[buffer[3]!] +
    '-' +
    byteToHex[buffer[4]!] +
    byteToHex[buffer[5]!] +
    '-' +
    byteToHex[buffer[6]!] +
    byteToHex[buffer[7]!] +
    '-' +
    byteToHex[buffer[8]!] +
    byteToHex[buffer[9]!] +
    '-' +
    byteToHex[buffer[10]!] +
    byteToHex[buffer[11]!] +
    byteToHex[buffer[12]!] +
    byteToHex[buffer[13]!] +
    byteToHex[buffer[14]!] +
    byteToHex[buffer[15]!]
  ).toLowerCase();
}

// RFC 9562 §5.4 — random UUID (v4).
export function randomUUID(options?: RandomUUIDOptions): string {
  validateRandomUUIDOptions(options);
  const buffer = new Buffer(16);
  randomFillSync(buffer, 0, 16);
  return serializeUUID(buffer, 4);
}

// RFC 9562 §5.7 — Unix-ms timestamped UUID (v7).
// Layout: 48-bit big-endian Unix-ms timestamp | 4-bit version (7) |
// 12 bits random | 2-bit variant (10) | 62 bits random.
export function randomUUIDv7(options?: RandomUUIDOptions): string {
  validateRandomUUIDOptions(options);
  const buffer = new Buffer(16);
  randomFillSync(buffer, 6, 10);

  const now = Date.now();
  const msb = Math.floor(now / 0x100000000);
  buffer[0] = (msb >>> 8) & 0xff;
  buffer[1] = msb & 0xff;
  buffer[2] = (now >>> 24) & 0xff;
  buffer[3] = (now >>> 16) & 0xff;
  buffer[4] = (now >>> 8) & 0xff;
  buffer[5] = now & 0xff;

  return serializeUUID(buffer, 7);
}
