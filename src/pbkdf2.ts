import { NativeQuickCrypto } from './NativeQuickCrypto/NativeQuickCrypto';
import { Buffer } from '@craftzdog/react-native-buffer';
import {
  type BinaryLike,
  binaryLikeToArrayBuffer,
  lazyDOMException,
  bufferLikeToArrayBuffer,
  normalizeHashName,
  HashContext,
} from './Utils';
import type { CryptoKey, SubtleAlgorithm } from './keys';
import { promisify } from 'util';

const WRONG_PASS =
  'Password must be a string, a Buffer, a typed array or a DataView';
const WRONG_SALT = `Salt must be a string, a Buffer, a typed array or a DataView`;

type Password = BinaryLike;
type Salt = BinaryLike;
type Pbkdf2Callback = (err: Error | null, derivedKey?: Buffer) => void;

function sanitizeInput(input: BinaryLike, errorMsg: string): ArrayBuffer {
  try {
    return binaryLikeToArrayBuffer(input);
  } catch (e: any) {
    throw errorMsg;
  }
}

const nativePbkdf2 = NativeQuickCrypto.pbkdf2;

export function pbkdf2(
  password: Password,
  salt: Salt,
  iterations: number,
  keylen: number,
  digest: string,
  callback: Pbkdf2Callback
): void;
export function pbkdf2(
  password: Password,
  salt: Salt,
  iterations: number,
  keylen: number,
  callback: Pbkdf2Callback
): void;
export function pbkdf2(
  password: Password,
  salt: Salt,
  iterations: number,
  keylen: number,
  arg0?: unknown,
  arg1?: unknown
): void {
  let digest = 'sha1';
  let callback: undefined | Pbkdf2Callback;
  if (typeof arg0 === 'string') {
    digest = arg0;
    if (typeof arg1 === 'function') {
      callback = arg1 as Pbkdf2Callback;
    }
  } else {
    if (typeof arg0 === 'function') {
      callback = arg0 as Pbkdf2Callback;
    }
  }
  if (callback === undefined) {
    throw new Error('No callback provided to pbkdf2');
  }

  const sanitizedPassword = sanitizeInput(password, WRONG_PASS);
  const sanitizedSalt = sanitizeInput(salt, WRONG_SALT);
  const normalizedDigest = normalizeHashName(digest, HashContext.Node);

  nativePbkdf2
    .pbkdf2(
      sanitizedPassword,
      sanitizedSalt,
      iterations,
      keylen,
      normalizedDigest
    )
    .then(
      (res: ArrayBuffer) => {
        callback!(null, Buffer.from(res));
      },
      (e: Error) => {
        callback!(e);
      }
    );
}

export function pbkdf2Sync(
  password: Password,
  salt: Salt,
  iterations: number,
  keylen: number,
  digest?: string
): ArrayBuffer {
  const sanitizedPassword = sanitizeInput(password, WRONG_PASS);
  const sanitizedSalt = sanitizeInput(salt, WRONG_SALT);

  const algo = digest ? normalizeHashName(digest, HashContext.Node) : 'sha1';
  let result: ArrayBuffer = nativePbkdf2.pbkdf2Sync(
    sanitizedPassword,
    sanitizedSalt,
    iterations,
    keylen,
    algo
  );

  return Buffer.from(result);
}

// We need this because the typescript  overload signatures in pbkdf2() above do
// not play nice with promisify() below.
const pbkdf2WithDigest = (
  password: Password,
  salt: Salt,
  iterations: number,
  keylen: number,
  digest: string,
  callback: Pbkdf2Callback
) => pbkdf2(password, salt, iterations, keylen, digest, callback);

const pbkdf2Promise = promisify(pbkdf2WithDigest);
export async function pbkdf2DeriveBits(
  algorithm: SubtleAlgorithm,
  baseKey: CryptoKey,
  length: number
): Promise<ArrayBuffer> {
  const { iterations, hash, salt } = algorithm;
  if (!hash || !hash.name) {
    throw lazyDOMException('hash cannot be blank', 'OperationError');
  }
  if (!iterations || iterations === 0) {
    throw lazyDOMException('iterations cannot be zero', 'OperationError');
  }
  if (!salt) {
    throw lazyDOMException(WRONG_SALT, 'OperationError');
  }
  const raw = baseKey.keyObject.export();

  if (length === 0)
    throw lazyDOMException('length cannot be zero', 'OperationError');
  if (length === null)
    throw lazyDOMException('length cannot be null', 'OperationError');
  if (length % 8) {
    throw lazyDOMException('length must be a multiple of 8', 'OperationError');
  }

  const sanitizedPassword = sanitizeInput(raw, WRONG_PASS);
  const sanitizedSalt = sanitizeInput(salt, WRONG_SALT);
  let result: Buffer | undefined = await pbkdf2Promise(
    sanitizedPassword,
    sanitizedSalt,
    iterations,
    length / 8,
    hash.name
  );
  if (!result) {
    throw lazyDOMException(
      'received bad result from pbkdf2()',
      'OperationError'
    );
  }
  return bufferLikeToArrayBuffer(result);
}
