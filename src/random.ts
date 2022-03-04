import { NativeFastCrypto } from './NativeFastCrypto/NativeFastCrypto';
import { Buffer } from '@craftzdog/react-native-buffer';

const random = NativeFastCrypto.random;
export function randomFill(...args) {
  const callback = args[args.length - 1];
  const rest = args.slice(0, -1);

  if (typeof callback !== 'function') {
    throw new Error('No callback provided to randomDill');
  }

  random.randomFill(...rest).then(
    () => {
      callback(undefined);
    },
    (e) => {
      callback(e);
    }
  );
}
export function randomFillSync(buffer, offset = 0, size) {
  return random.randomFillSync(buffer, offset, size);
}

export function randomBytes(size, callback) {
  const buf = new Buffer(size);

  if (callback === undefined) {
    randomFillSync(buf.buffer, 0, size);
    return buf;
  }

  // Keep the callback as a regular function so this is propagated.
  randomFill(buf.buffer, 0, size, function(error) {
    if (error) {
      callback(error);
    }
    callback(undefined, buf);
  });
}
