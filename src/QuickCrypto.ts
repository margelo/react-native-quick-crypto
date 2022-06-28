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
  privateDecrypt,
  generateKeyPair,
  generateKeyPairSync,
  constants,
  ...pbkdf2,
  ...random,
};
