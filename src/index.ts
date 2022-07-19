import { QuickCrypto } from './QuickCrypto';
const fallbackCrypto = require('crypto-browserify');
const crypto = {...fallbackCrypto, ...QuickCrypto};

module.exports = crypto;
export default crypto;
