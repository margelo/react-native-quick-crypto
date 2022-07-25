import { Buffer } from '@craftzdog/react-native-buffer';
import { QuickCrypto } from './QuickCrypto';

// @ts-expect-error
global.Buffer = Buffer;
// @ts-expect-error
global.crypto = QuickCrypto; // for randombytes https://github.com/crypto-browserify/randombytes/blob/master/browser.js#L16

const fallbackCrypto = require('crypto-browserify');
const crypto = { ...fallbackCrypto, ...QuickCrypto }; // Maybe use proxy to not load everything?
global.crypto = crypto;

module.exports = crypto;
export default crypto;
