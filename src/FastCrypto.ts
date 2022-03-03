import { NativeFastCrypto } from './NativeFastCrypto/NativeFastCrypto';
import { Buffer } from '@craftzdog/react-native-buffer';
import { isBuffer, toArrayBuffer } from './Utils';

async function runAsync(): Promise<number> {
  return NativeFastCrypto.runAsync();
}

const nativePbkdf2 = NativeFastCrypto.pbkdf2;
function pbkdf2(...args) {
  const callback = args[args.length - 1];
  const rest = args.slice(0, -1);

  if (typeof callback !== 'function') {
    throw 'No callback provided to pbkdf2';
  }

  if (typeof args[0] === 'string') {
    const buffer = Buffer.from(args[0]);
    rest[0] = buffer.buffer.slice(
      buffer.byteOffset,
      buffer.byteOffset + buffer.byteLength
    );
  }
  if (typeof args[1] === 'string') {
    const buffer = Buffer.from(args[1]);
    rest[1] = buffer.buffer.slice(
      buffer.byteOffset,
      buffer.byteOffset + buffer.byteLength
    );
  }
  if (isBuffer(args[0])) {
    rest[0] = toArrayBuffer(args[0]);
  }
  if (isBuffer(args[1])) {
    rest[1] = toArrayBuffer(args[1]);
  }
  if (!(rest[1] instanceof ArrayBuffer)) {
    throw `Salt must be a string, a Buffer, a typed array or a DataView`;
  }
  if (!(rest[0] instanceof ArrayBuffer)) {
    throw 'Password must be a string, a Buffer, a typed array or a DataView';
  }
  if (rest.length === 4) {
    rest.push('sha1');
  }

  nativePbkdf2.pbkdf2(...rest).then(
    (res) => {
      callback(undefined, res);
    },
    (e) => {
      callback(e);
    }
  );
}

function pbkdf2Sync(...args) {
  if (typeof args[0] === 'string') {
    const buffer = Buffer.from(args[0]);
    args[0] = buffer.buffer.slice(
      buffer.byteOffset,
      buffer.byteOffset + buffer.byteLength
    );
  }
  if (typeof args[1] === 'string') {
    const buffer = Buffer.from(args[1]);
    args[1] = buffer.buffer.slice(
      buffer.byteOffset,
      buffer.byteOffset + buffer.byteLength
    );
  }
  if (isBuffer(args[0])) {
    args[0] = toArrayBuffer(args[0]);
  }
  if (isBuffer(args[1])) {
    args[1] = toArrayBuffer(args[1]);
  }
  if (!(args[1] instanceof ArrayBuffer)) {
    throw 'Salt must be a string, a Buffer, a typed array or a DataView';
  }
  if (!(args[0] instanceof ArrayBuffer)) {
    throw 'Password must be a string, a Buffer, a typed array or a DataView';
  }
  if (args.length === 4) {
    args.push('sha1');
  }

  return nativePbkdf2.pbkdf2Sync(...args);
}

export const FastCrypto = {
  runAsync,
  createHmac: NativeFastCrypto.createHmac,
  pbkdf2,
  pbkdf2Sync,
};
