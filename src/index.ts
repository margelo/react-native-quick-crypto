/* global Crypto */
import '@craftzdog/react-native-buffer';

const crypto = new Proxy({} as Crypto, {
  get: (_, p) => {
    // Try to load from C++ QuickCrypto, otherwise fall back to browserify
    return require('./QuickCrypto')[p] ?? require('crypto-browserify')[p];
  },
});

// for randombytes https://github.com/crypto-browserify/randombytes/blob/master/browser.js#L16
global.crypto = crypto;

module.exports = crypto;
export default crypto;
