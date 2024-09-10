// polyfill imports
import { Buffer } from '@craftzdog/react-native-buffer';

// API imports
import { pbkdf2 } from './pbkdf2';
import * as random from './random';

// utils import
import * as conversion_utils from './utils/conversion';

/**
 * Loosely matches Node.js {crypto} with some unimplemented functionality.
 * See `docs/implementation-coverage.md` for status.
 */
const QuickCrypto = {
  // createHmac,
  // Hmac: createHmac,
  // Hash: createHash,
  // createHash,
  // createCipher,
  // createCipheriv,
  // createDecipher,
  // createDecipheriv,
  // createPublicKey,
  // createPrivateKey,
  // createSecretKey,
  // publicEncrypt,
  // publicDecrypt,
  // privateDecrypt,
  // generateKey,
  // generateKeyPair,
  // generateKeyPairSync,
  // generateKeySync,
  // createSign,
  // createVerify,
  // subtle,
  // constants,
  ...pbkdf2,
  ...random,
  // getCiphers,
  // getHashes,
  // webcrypto,
  ...conversion_utils,
};

/**
 * Optional. Patch global.crypto with quickcrypto and global.Buffer with react-native-buffer.
 */
export const install = () => {
  // @ts-expect-error copyBytesFrom and poolSizets are missing from react-native-buffer
  global.Buffer = Buffer;

  // @ts-expect-error subtle isn't fully implemented and Cryptokey is missing
  global.crypto = QuickCrypto;
};

// random, cipher, hash use nextTick
global.process.nextTick = setImmediate;

export default QuickCrypto;

// Additional exports for CommonJS compatibility
module.exports = QuickCrypto;
module.exports.default = QuickCrypto;
module.exports.install = install;
