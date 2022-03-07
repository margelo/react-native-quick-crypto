import { NativeFastCrypto } from './NativeFastCrypto/NativeFastCrypto';
import { Buffer } from '@craftzdog/react-native-buffer';
import { BinaryLike, binaryLikeToArrayBuffer } from './Utils';

const WRONG_PASS =
  'Password must be a string, a Buffer, a typed array or a DataView';
const WRON_SALT = `Salt must be a string, a Buffer, a typed array or a DataView`;

type Password = BinaryLike;
type Salt = BinaryLike;

function sanitizeInput(input: BinaryLike, errorMsg: string): ArrayBuffer {
  try {
    return binaryLikeToArrayBuffer(input);
  } catch (e: any) {
    throw errorMsg;
  }
}

const nativePbkdf2 = NativeFastCrypto.pbkdf2;

export function pbkdf2(
  password: Password,
  salt: Salt,
  iterations: number,
  keylen: number,
  digest: string,
  callback: (err: Error | null, derivedKey?: Buffer) => void
) {
  if (typeof callback !== 'function') {
    throw new Error('No callback provided to pbkdf2');
  }

  const sanitizedPassword = sanitizeInput(password, WRONG_PASS);
  const sanitizedSalt = sanitizeInput(salt, WRON_SALT);

  nativePbkdf2
    .pbkdf2(sanitizedPassword, sanitizedSalt, iterations, keylen, digest)
    .then(
      (res: ArrayBuffer) => {
        callback(null, Buffer.from(res));
      },
      (e: Error) => {
        callback(e);
      }
    );
}
export function pbkdf2Sync(
  password: Password,
  salt: Salt,
  iterations: number,
  keylen: number,
  digest?: string
): Buffer {
  const sanitizedPassword = sanitizeInput(password, WRONG_PASS);
  const sanitizedSalt = sanitizeInput(salt, WRON_SALT);

  const algo = digest ? digest : 'sha1';
  let result: ArrayBuffer = nativePbkdf2.pbkdf2Sync(
    sanitizedPassword,
    sanitizedSalt,
    iterations,
    keylen,
    algo
  );

  return Buffer.from(result);
}
