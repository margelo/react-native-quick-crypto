import { NitroModules } from 'react-native-nitro-modules';
import { Buffer } from '@craftzdog/react-native-buffer';
import type { Prime as NativePrime } from './specs/prime.nitro';
import type { BinaryLike } from './utils';
import { binaryLikeToArrayBuffer } from './utils';

let native: NativePrime;
function getNative(): NativePrime {
  if (native == null) {
    native = NitroModules.createHybridObject<NativePrime>('Prime');
  }
  return native;
}

export interface GeneratePrimeOptions {
  safe?: boolean;
  bigint?: boolean;
  add?: ArrayBuffer | Buffer | Uint8Array;
  rem?: ArrayBuffer | Buffer | Uint8Array;
}

export interface CheckPrimeOptions {
  checks?: number;
}

function toOptionalArrayBuffer(
  value?: ArrayBuffer | Buffer | Uint8Array,
): ArrayBuffer | undefined {
  if (value == null) return undefined;
  if (value instanceof ArrayBuffer) return value;
  return binaryLikeToArrayBuffer(value);
}

function bufferToBigInt(buf: Buffer): bigint {
  let result = 0n;
  for (let i = 0; i < buf.length; i++) {
    result = (result << 8n) | BigInt(buf[i]!);
  }
  return result;
}

function bigIntToBuffer(value: bigint): ArrayBuffer {
  if (value === 0n) return new Uint8Array([0]).buffer;
  const hex = value.toString(16);
  const paddedHex = hex.length % 2 ? '0' + hex : hex;
  const bytes = new Uint8Array(paddedHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(paddedHex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes.buffer;
}

export function generatePrimeSync(
  size: number,
  options?: GeneratePrimeOptions,
): Buffer | bigint {
  const safe = options?.safe ?? false;
  const add = toOptionalArrayBuffer(options?.add);
  const rem = toOptionalArrayBuffer(options?.rem);
  const result = Buffer.from(
    getNative().generatePrimeSync(size, safe, add, rem),
  );
  if (options?.bigint) {
    return bufferToBigInt(result);
  }
  return result;
}

export function generatePrime(
  size: number,
  options?: GeneratePrimeOptions,
  callback?: (err: Error | null, prime: Buffer | bigint) => void,
): void {
  if (typeof options === 'function') {
    callback = options as unknown as (
      err: Error | null,
      prime: Buffer | bigint,
    ) => void;
    options = {};
  }
  const safe = options?.safe ?? false;
  const add = toOptionalArrayBuffer(options?.add);
  const rem = toOptionalArrayBuffer(options?.rem);
  const wantBigint = options?.bigint ?? false;

  getNative()
    .generatePrime(size, safe, add, rem)
    .then(ab => {
      const result = Buffer.from(ab);
      if (wantBigint) {
        callback?.(null, bufferToBigInt(result));
      } else {
        callback?.(null, result);
      }
    })
    .catch((err: Error) => callback?.(err, Buffer.alloc(0)));
}

export function checkPrimeSync(
  candidate: BinaryLike | bigint,
  options?: CheckPrimeOptions,
): boolean {
  const checks = options?.checks ?? 0;
  const buf =
    typeof candidate === 'bigint'
      ? bigIntToBuffer(candidate)
      : binaryLikeToArrayBuffer(candidate);
  return getNative().checkPrimeSync(buf, checks);
}

export function checkPrime(
  candidate: BinaryLike | bigint,
  options?: CheckPrimeOptions | ((err: Error | null, result: boolean) => void),
  callback?: (err: Error | null, result: boolean) => void,
): void {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  const checks = (options as CheckPrimeOptions)?.checks ?? 0;
  const buf =
    typeof candidate === 'bigint'
      ? bigIntToBuffer(candidate)
      : binaryLikeToArrayBuffer(candidate);

  getNative()
    .checkPrime(buf, checks)
    .then(result => callback?.(null, result))
    .catch((err: Error) => callback?.(err, false));
}
