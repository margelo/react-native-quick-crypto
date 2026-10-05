// Jest mock: forwards to node:crypto. See docs/content/docs/guides/testing-with-jest.mdx.
const crypto = require('node:crypto');
const { Buffer } = require('node:buffer');

const QuickCrypto = {
  ...crypto,
  Buffer,
  CryptoKey: globalThis.CryptoKey,
  install: () => {},
};

module.exports = {
  __esModule: true,
  default: QuickCrypto,
  ...QuickCrypto,
};
