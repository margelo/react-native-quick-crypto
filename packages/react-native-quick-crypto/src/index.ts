// polyfill imports
import { Buffer } from '@craftzdog/react-native-buffer';

// API imports
import * as keys from './keys';
import * as cipher from './cipher';
import * as ed from './ed';
import { hashExports as hash } from './hash';
import { hmacExports as hmac } from './hmac';
import * as pbkdf2 from './pbkdf2';
import * as random from './random';

// utils import
import * as utils from './utils';

/**
 * Loosely matches Node.js {crypto} with some unimplemented functionality.
 * See `docs/implementation-coverage.md` for status.
 */
const QuickCrypto = {
  ...keys,
  ...cipher,
  ...ed,
  ...hash,
  ...hmac,
  ...pbkdf2,
  ...random,
  ...utils,
};

/**
 * Optional. Patch global.crypto with react-native-quick-crypto and
 * global.Buffer with react-native-buffer.
 */
export const install = () => {
  // @ts-expect-error copyBytesFrom and poolSizets are missing from react-native-buffer
  global.Buffer = Buffer;

  // @ts-expect-error subtle isn't fully implemented and Cryptokey is missing
  global.crypto = QuickCrypto;
};

// random, cipher, hash use nextTick
global.process.nextTick = setImmediate;

// exports
export default QuickCrypto;
export * from './cipher';
export * from './ed';
export * from './hash';
export * from './hmac';
export * from './pbkdf2';
export * from './random';
export * from './utils';

// Additional exports for CommonJS compatibility
module.exports = QuickCrypto;
module.exports.default = QuickCrypto;
module.exports.install = install;
