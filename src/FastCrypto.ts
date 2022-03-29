import * as pbkdf2 from './pbkdf2';
import * as random from './random';
import { createHmac } from './Hmac';
import { createHash } from './Hash';

export const FastCrypto = {
  createHmac,
  Hmac: createHmac,
  Hash: createHash,
  createHash,
  ...pbkdf2,
  ...random,
};
