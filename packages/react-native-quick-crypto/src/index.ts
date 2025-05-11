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
import webcrypto from './webcrypto';
import * as keys from './keys';
import * as utils from './Utils';
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
  ...keys,
  ...pbkdf2,
  ...random,
  ...utils,
  webcrypto,
};

// type exports
export type * from './keys';
export type * from './random';
export type * from './Cipher';
export type * from './Utils';

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
