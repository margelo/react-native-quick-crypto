import { NativeFastCrypto } from './NativeFastCrypto/NativeFastCrypto';
import { Buffer } from '@craftzdog/react-native-buffer';
import { isBuffer, toArrayBuffer } from './Utils';

function sanitizeInput(input, output) {
  if (output == null) {
    output = input;
  }

  const messages = [
    'Password must be a string, a Buffer, a typed array or a DataView',
    `Salt must be a string, a Buffer, a typed array or a DataView`,
  ];

  [0, 1].forEach((key: number) => {
    if (typeof input[key] === 'string') {
      const buffer = Buffer.from(input[key], 'utf-8');
      output[key] = buffer.buffer.slice(
        buffer.byteOffset,
        buffer.byteOffset + buffer.byteLength
      );
    }

    if (isBuffer(input[key])) {
      output[key] = toArrayBuffer(input[key]);
    }

    if (!(output[key] instanceof ArrayBuffer)) {
      try {
        const buffer = Buffer.from(input[key]);
        output[key] = buffer.buffer.slice(
          buffer.byteOffset,
          buffer.byteOffset + buffer.byteLength
        );
      } catch {
        throw messages[key];
      }
    }
  });
}
const nativePbkdf2 = NativeFastCrypto.pbkdf2;
export function pbkdf2(...args) {
  const callback = args[args.length - 1];
  const rest = args.slice(0, -1);

  if (typeof callback !== 'function') {
    throw new Error('No callback provided to pbkdf2');
  }

  sanitizeInput(args, rest);

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
export function pbkdf2Sync(...args) {
  const argsOutput = args;
  sanitizeInput(args, argsOutput);

  if (argsOutput.length === 4) {
    argsOutput.push('sha1');
  }

  return nativePbkdf2.pbkdf2Sync(...argsOutput);
}
