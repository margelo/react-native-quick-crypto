import { NativeFastCrypto } from './NativeFastCrypto/NativeFastCrypto';
import { Buffer } from '@craftzdog/react-native-buffer';

const random = NativeFastCrypto.random;

type TypedArray =
  | Uint8Array
  | Uint8ClampedArray
  | Uint16Array
  | Uint32Array
  | Int8Array
  | Int16Array
  | Int32Array
  | Float32Array
  | Float64Array;
type ArrayBufferView = TypedArray | DataView;

export function randomFill<T extends ArrayBufferView>(
  buffer: T,
  callback: (err: Error | null, buf?: ArrayBuffer) => T
): void;

export function randomFill<T extends ArrayBufferView>(
  buffer: T,
  offset: number,
  callback: (err: Error | null, buf?: ArrayBuffer) => T
): void;

export function randomFill<T extends ArrayBufferView>(
  buffer: T,
  offset: number,
  size: number,
  callback: (err: Error | null, buf?: ArrayBuffer) => T
): void;

export function randomFill<T extends ArrayBufferView>(
  buffer: T,
  ...rest: any[]
): void {
  if (typeof rest[rest.length - 1] !== 'function') {
    throw new Error('No callback provided to randomDill');
  }

  const callback = rest[rest.length - 1] as any as (
    err: Error | null,
    buf?: ArrayBuffer
  ) => void;

  let offset: number = 0;
  let size: number = buffer.byteLength;

  if (typeof rest[2] === 'function') {
    offset = rest[0];
    size = rest[1];
  }

  if (typeof rest[1] === 'function') {
    offset = rest[0];
  }

  random.randomFill(buffer.buffer ? buffer.buffer : buffer, offset, size).then(
    () => {
      callback(null, buffer);
    },
    (e: Error) => {
      callback(e);
    }
  );
}

export function randomFillSync<T extends ArrayBufferView>(
  buffer: T,
  offset: number = 0,
  size?: number
) {
  random.randomFillSync(
    buffer.buffer ? buffer.buffer : buffer,
    offset,
    size ?? buffer.byteLength
  );
  return buffer;
}

export function randomBytes(size: number): ArrayBuffer;

export function randomBytes(
  size: number,
  callback: (err: Error | null, buf?: ArrayBuffer) => void
): void;

export function randomBytes(
  size: number,
  callback?: (err: Error | null, buf?: ArrayBuffer) => void
): void | ArrayBuffer {
  const buf = new Buffer(size);

  if (callback === undefined) {
    randomFillSync(buf.buffer, 0, size);
    return buf;
  }

  randomFill(buf.buffer, 0, size, (error: Error | null) => {
    if (error) {
      callback(error);
    }
    callback(null, buf);
  });
}

type RandomIntCallback = (err: Error | null, value?: number) => void;
type Task = {
  min: number;
  max: number;
  callback: RandomIntCallback;
};

// Largest integer we can read from a buffer.
// e.g.: Buffer.from("ff".repeat(6), "hex").readUIntBE(0, 6);
const RAND_MAX = 0xffff_ffff_ffff;

// Cache random data to use in randomInt. The cache size must be evenly
// divisible by 6 because each attempt to obtain a random int uses 6 bytes.
const randomCache = new Buffer(6 * 1024);
let randomCacheOffset = randomCache.length;
let asyncCacheFillInProgress = false;
const asyncCachePendingTasks: Task[] = [];

// taken from https://github.com/nodejs/node/blob/master/lib/internal/crypto/random.js
// Generates an integer in [min, max) range where min is inclusive and max is
// exclusive.

export function randomInt(max: number, callback: RandomIntCallback): void;
export function randomInt(max: number): number;
export function randomInt(
  min: number,
  max: number,
  callback: RandomIntCallback
): void;
export function randomInt(min: number, max: number): number;
export function randomInt(
  arg1: number,
  arg2?: number | RandomIntCallback,
  callback?: RandomIntCallback
): void | number {
  // Detect optional min syntax
  // randomInt(max)
  // randomInt(max, callback)
  let max: number;
  let min: number;
  const minNotSpecified =
    typeof arg2 === 'undefined' || typeof arg2 === 'function';

  if (minNotSpecified) {
    callback = arg2;
    max = arg1;
    min = 0;
  } else {
    min = arg1;
    max = arg2;
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
      process.nextTick(callback as Function, undefined, n);
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
  randomFill(randomCache, (err) => {
    asyncCacheFillInProgress = false;

    const tasks = asyncCachePendingTasks;
    const errorReceiver = err && tasks.shift();
    if (!err) randomCacheOffset = 0;

    // Restart all pending tasks. If an error occurred, we only notify a single
    // callback (errorReceiver) about it. This way, every async call to
    // randomInt has a chance of being successful, and it avoids complex
    // exception handling here.
    tasks.splice(0).forEach((task) => {
      randomInt(task.min, task.max, task.callback);
    });

    // This is the only call that might throw, and is therefore done at the end.
    if (errorReceiver) errorReceiver.callback(err);
  });
}
