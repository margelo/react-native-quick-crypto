import { Buffer } from '@craftzdog/react-native-buffer';
import * as pbkdf2 from './pbkdf2';
import * as random from './random';
import {
  createCipher,
  createCipheriv,
  createDecipher,
  createDecipheriv,
  publicEncrypt,
  publicDecrypt,
  privateDecrypt,
  generateKeyPair,
  generateKeyPairSync,
} from './Cipher';
import { generateKey, generateKeySync } from './keygen';
import { createSign, createVerify } from './sig';
import { createHmac } from './Hmac';
import { createHash } from './Hash';
import { constants } from './constants';
import { subtle } from './subtle';
import { getCiphers, getHashes } from './utils';
import webcrypto from './webcrypto';
import { createPrivateKey, createPublicKey, createSecretKey } from './keys';

/**
 * Loosely matches Node.js {crypto} with some unimplemented functionality
 */
const QuickCrypto = {
  createHmac,
  Hmac: createHmac,
  Hash: createHash,
  createHash,
  createCipher,
  createCipheriv,
  createDecipher,
  createDecipheriv,
  createPublicKey,
  createPrivateKey,
  createSecretKey,
  publicEncrypt,
  publicDecrypt,
  privateDecrypt,
  generateKey,
  generateKeyPair,
  generateKeyPairSync,
  generateKeySync,
  createSign,
  createVerify,
  subtle,
  constants,
  ...pbkdf2,
  ...random,
  getCiphers,
  getHashes,
  webcrypto,
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

export default QuickCrypto;

// Additional exports for CommonJS compatibility
module.exports = QuickCrypto;
module.exports.default = QuickCrypto;
module.exports.install = install;
