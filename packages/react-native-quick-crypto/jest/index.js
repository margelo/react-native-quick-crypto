/**
 * Jest mock for react-native-quick-crypto.
 *
 * Jest runs on Node, which already implements the `crypto` API this library
 * brings to React Native, so the mock forwards to `node:crypto` instead of
 * stubbing each function. Results are real (hashes, ciphertexts, signatures),
 * so tests exercise the same behavior as the app.
 *
 * Usage, in a Jest setup file or at the top of a test:
 *
 *   jest.mock('react-native-quick-crypto', () =>
 *     require('react-native-quick-crypto/jest')
 *   );
 *
 * APIs that Node does not provide (for example blake3 or ML-KEM) are not
 * included; mock those yourself if your code uses them.
 */
const crypto = require('node:crypto');
const { Buffer } = require('node:buffer');

const QuickCrypto = {
  ...crypto,
  Buffer,
  // The app may call install() to patch globals; Node already has
  // globalThis.crypto and Buffer, so there is nothing to do here.
  install: () => {},
};

module.exports = {
  __esModule: true,
  default: QuickCrypto,
  ...QuickCrypto,
};
