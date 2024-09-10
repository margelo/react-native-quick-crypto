import { Buffer } from '@craftzdog/react-native-buffer';
import { NitroModules } from 'react-native-nitro-modules';
import type { BinaryLike } from './utils';
import {
  HashContext,
  binaryLikeToArrayBuffer,
  bufferLikeToArrayBuffer,
  lazyDOMException,
  normalizeHashName,
} from './utils';
import type { HashAlgorithm, SubtleAlgorithm } from './utils';
import type { Pbkdf2 } from './specs/pbkdf2.nitro';
import { promisify } from 'util';
import type { CryptoKey } from './keys';

const WRONG_PASS =
  'Password must be a string, a Buffer, a typed array or a DataView';
const WRONG_SALT = `Salt must be a string, a Buffer, a typed array or a DataView`;

type Password = BinaryLike;
type Salt = BinaryLike;
type Pbkdf2Callback = (err: Error | null, derivedKey?: Buffer) => void;

// to use native bits in sub-functions, use getNative(). don't call it at top-level!
let native: Pbkdf2;
function getNative(): Pbkdf2 {
  if (native == null) {
    // lazy-load the Nitro HybridObject
    native = NitroModules.createHybridObject<Pbkdf2>('Pbkdf2');
  }
  return native;
}

function sanitizeInput(input: BinaryLike, errorMsg: string): ArrayBuffer {
  try {
    return binaryLikeToArrayBuffer(input);
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
  } catch (_e: unknown) {
    throw new Error(errorMsg);
  }
}

export function pbkdf2(
  password: Password,
  salt: Salt,
  iterations: number,
  keylen: number,
  digest: string,
  callback: Pbkdf2Callback,
): void {
  if (callback === undefined || typeof callback !== 'function') {
    throw new Error('No callback provided to pbkdf2');
  }
  const sanitizedPassword = sanitizeInput(password, WRONG_PASS);
  const sanitizedSalt = sanitizeInput(salt, WRONG_SALT);
  const normalizedDigest = normalizeHashName(digest, HashContext.Node);

  getNative();
  native
    .pbkdf2(
      sanitizedPassword,
      sanitizedSalt,
      iterations,
      keylen,
      normalizedDigest,
    )
    .then(
      (res: ArrayBuffer) => {
        callback!(null, Buffer.from(res));
      },
      (e: Error) => {
        callback!(e);
      },
    );
}

export function pbkdf2Sync(
  password: Password,
  salt: Salt,
  iterations: number,
  keylen: number,
  digest?: HashAlgorithm,
): ArrayBuffer {
  const sanitizedPassword = sanitizeInput(password, WRONG_PASS);
  const sanitizedSalt = sanitizeInput(salt, WRONG_SALT);

  const algo = digest ? normalizeHashName(digest, HashContext.Node) : 'sha1';
  getNative();
  const result: ArrayBuffer = native.pbkdf2Sync(
    sanitizedPassword,
    sanitizedSalt,
    iterations,
    keylen,
    algo,
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
  digest: HashAlgorithm,
  callback: Pbkdf2Callback,
) => pbkdf2(password, salt, iterations, keylen, digest, callback);

const pbkdf2Promise = promisify(pbkdf2WithDigest);
export async function pbkdf2DeriveBits(
  algorithm: SubtleAlgorithm,
  baseKey: CryptoKey,
  length: number,
): Promise<ArrayBuffer> {
  const { iterations, hash, salt } = algorithm;
  const normalizedHash = normalizeHashName(hash);
  if (!normalizedHash) {
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
  const result: Buffer | undefined = await pbkdf2Promise(
    sanitizedPassword,
    sanitizedSalt,
    iterations,
    length / 8,
    normalizedHash as HashAlgorithm,
  );
  if (!result) {
    throw lazyDOMException(
      'received bad result from pbkdf2()',
      'OperationError',
    );
  }
  return bufferLikeToArrayBuffer(result);
}
