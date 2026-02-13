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

function validateAlgorithm(algorithm: string): void {
  if (
    algorithm !== 'argon2d' &&
    algorithm !== 'argon2i' &&
    algorithm !== 'argon2id'
  ) {
    throw new TypeError(`Unknown argon2 algorithm: ${algorithm}`);
  }
}

function toAB(value: BinaryLike): ArrayBuffer {
  return binaryLikeToArrayBuffer(value);
}

export function argon2Sync(algorithm: string, params: Argon2Params): Buffer {
  validateAlgorithm(algorithm);
  const version = params.version ?? ARGON2_VERSION;
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
