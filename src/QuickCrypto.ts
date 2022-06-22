import * as pbkdf2 from './pbkdf2';
import * as random from './random';
import {
  createCipher,
  createCipheriv,
  createDecipher,
  createDecipheriv,
  publicEncrypt,
  publicDecrypt,
  generateKeyPair
} from './Cipher';
import { createHmac } from './Hmac';
import { createHash } from './Hash';
import { constants } from './constants';

export const QuickCrypto = {
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
  generateKeyPair,
  constants,
  ...pbkdf2,
  ...random,
};
