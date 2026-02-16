// polyfill imports
import { Buffer } from '@craftzdog/react-native-buffer';

// API imports
import * as argon2Module from './argon2';
import * as keys from './keys';
import * as blake3 from './blake3';
import * as cipher from './cipher';
import * as ed from './ed';
import { hashExports as hash } from './hash';
import { hmacExports as hmac } from './hmac';
import * as hkdf from './hkdf';
import * as pbkdf2 from './pbkdf2';
import * as prime from './prime';
import * as scrypt from './scrypt';
import * as random from './random';
import * as ecdh from './ecdh';
import * as dh from './diffie-hellman';
import { Certificate } from './certificate';
import { X509Certificate } from './x509certificate';
import { getCurves } from './ec';
import { constants } from './constants';

// utils import
import * as utils from './utils';
import * as subtle from './subtle';

/**
 * Loosely matches Node.js {crypto} with some unimplemented functionality.
 * See `docs/implementation-coverage.md` for status.
 */
const QuickCrypto = {
  ...argon2Module,
  ...keys,
  ...blake3,
  ...cipher,
  ...ed,
  ...hash,
  ...hmac,
  ...hkdf,
  ...pbkdf2,
  ...prime,
  ...scrypt,
  ...random,
  ...ecdh,
  ...dh,
  ...utils,
  ...subtle,
  Certificate,
  X509Certificate,
  getCurves,
  constants,
  Buffer,
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

  // Install base64 globals (base64ToArrayBuffer, base64FromArrayBuffer)
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  require('react-native-quick-base64');
};

// random, cipher, hash use nextTick
if (global.process == null) {
  // @ts-expect-error - process is not defined
  global.process = {};
}
if (global.process.nextTick == null) {
  global.process.nextTick = setImmediate;
}

// exports
export default QuickCrypto;
export * from './argon2';
export * from './blake3';
export { Certificate } from './certificate';
export { X509Certificate } from './x509certificate';
export type { CheckOptions, X509LegacyObject } from './x509certificate';
export * from './cipher';
export * from './ed';
export * from './keys';
export * from './hash';
export * from './hmac';
export * from './hkdf';
export * from './pbkdf2';
export * from './prime';
export * from './scrypt';
export * from './random';
export * from './ecdh';
export { getCurves } from './ec';
export * from './diffie-hellman';
export * from './utils';
export * from './subtle';
export { subtle, isCryptoKeyPair } from './subtle';
export { constants } from './constants';
export { Buffer } from '@craftzdog/react-native-buffer';

// Additional exports for CommonJS compatibility
module.exports = QuickCrypto;
module.exports.default = QuickCrypto;
module.exports.install = install;
