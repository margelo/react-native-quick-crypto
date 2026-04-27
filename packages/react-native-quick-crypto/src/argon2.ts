import { Buffer } from '@craftzdog/react-native-buffer';
import { NitroModules } from 'react-native-nitro-modules';
import type { Argon2 as NativeArgon2 } from './specs/argon2.nitro';
import { binaryLikeToArrayBuffer } from './utils';
import type { BinaryLike } from './utils';

let native: NativeArgon2;
function getNative(): NativeArgon2 {
  if (native == null) {
    native = NitroModules.createHybridObject<NativeArgon2>('Argon2');
  }
  return native;
}

export interface Argon2Params {
  message: BinaryLike;
  nonce: BinaryLike;
  parallelism: number;
  tagLength: number;
  memory: number;
  passes: number;
  secret?: BinaryLike;
  associatedData?: BinaryLike;
  version?: number;
}

const ARGON2_VERSION = 0x13; // v1.3

// RFC 9106 § 3.1: Argon2 input/parameter constraints.
//   p (parallelism)   1   ≤ p ≤ 2^24 - 1
//   T (tag length)    4   ≤ T ≤ 2^32 - 1
//   m (memory in KiB) 8*p ≤ m ≤ 2^32 - 1
//   t (passes)        1   ≤ t ≤ 2^32 - 1
//   |salt| (nonce)    8   ≤ |s| ≤ 2^32 - 1
//   v (version)       0x10 (v1.0) or 0x13 (v1.3)
const ARGON2_MAX_U24 = 0xff_ffff;
const ARGON2_MAX_U32 = 0xffff_ffff;

function isUInt(value: unknown, max: number): value is number {
  return (
    typeof value === 'number' &&
    Number.isFinite(value) &&
    Number.isInteger(value) &&
    value >= 0 &&
    value <= max
  );
}

function validateAlgorithm(algorithm: string): void {
  if (
    algorithm !== 'argon2d' &&
    algorithm !== 'argon2i' &&
    algorithm !== 'argon2id'
  ) {
    throw new TypeError(`Unknown argon2 algorithm: ${algorithm}`);
  }
}

function validateArgon2Params(params: Argon2Params, version: number): void {
  if (!isUInt(params.parallelism, ARGON2_MAX_U24) || params.parallelism < 1) {
    throw new RangeError(
      `Invalid Argon2 parallelism: ${params.parallelism} ` +
        `(RFC 9106: 1 ≤ p ≤ 2^24 - 1)`,
    );
  }
  if (!isUInt(params.tagLength, ARGON2_MAX_U32) || params.tagLength < 4) {
    throw new RangeError(
      `Invalid Argon2 tagLength: ${params.tagLength} ` +
        `(RFC 9106: 4 ≤ T ≤ 2^32 - 1)`,
    );
  }
  const minMemory = 8 * params.parallelism;
  if (!isUInt(params.memory, ARGON2_MAX_U32) || params.memory < minMemory) {
    throw new RangeError(
      `Invalid Argon2 memory: ${params.memory} KiB ` +
        `(RFC 9106: 8 * p (= ${minMemory}) ≤ m ≤ 2^32 - 1)`,
    );
  }
  if (!isUInt(params.passes, ARGON2_MAX_U32) || params.passes < 1) {
    throw new RangeError(
      `Invalid Argon2 passes: ${params.passes} ` +
        `(RFC 9106: 1 ≤ t ≤ 2^32 - 1)`,
    );
  }
  if (version !== 0x10 && version !== 0x13) {
    throw new RangeError(
      `Invalid Argon2 version: 0x${version.toString(16)} ` +
        `(RFC 9106: 0x10 or 0x13)`,
    );
  }
  // Salt (nonce) must be 8..2^32 - 1 bytes — measured against the resolved
  // ArrayBuffer because BinaryLike accepts strings whose UTF-8 length is
  // what actually reaches OpenSSL.
  const nonceLen = binaryLikeToArrayBuffer(params.nonce).byteLength;
  if (nonceLen < 8 || nonceLen > ARGON2_MAX_U32) {
    throw new RangeError(
      `Invalid Argon2 nonce length: ${nonceLen} bytes ` +
        `(RFC 9106: 8 ≤ |s| ≤ 2^32 - 1)`,
    );
  }
}

function toAB(value: BinaryLike): ArrayBuffer {
  return binaryLikeToArrayBuffer(value);
}

export function argon2Sync(algorithm: string, params: Argon2Params): Buffer {
  validateAlgorithm(algorithm);
  const version = params.version ?? ARGON2_VERSION;
  validateArgon2Params(params, version);
  const result = getNative().hashSync(
    algorithm,
    toAB(params.message),
    toAB(params.nonce),
    params.parallelism,
    params.tagLength,
    params.memory,
    params.passes,
    version,
    params.secret ? toAB(params.secret) : undefined,
    params.associatedData ? toAB(params.associatedData) : undefined,
  );
  return Buffer.from(result);
}

export function argon2(
  algorithm: string,
  params: Argon2Params,
  callback: (err: Error | null, result: Buffer) => void,
): void {
  validateAlgorithm(algorithm);
  const version = params.version ?? ARGON2_VERSION;
  try {
    validateArgon2Params(params, version);
  } catch (err) {
    callback(err as Error, Buffer.alloc(0));
    return;
  }
  getNative()
    .hash(
      algorithm,
      toAB(params.message),
      toAB(params.nonce),
      params.parallelism,
      params.tagLength,
      params.memory,
      params.passes,
      version,
      params.secret ? toAB(params.secret) : undefined,
      params.associatedData ? toAB(params.associatedData) : undefined,
    )
    .then(ab => callback(null, Buffer.from(ab)))
    .catch((err: Error) => callback(err, Buffer.alloc(0)));
}
