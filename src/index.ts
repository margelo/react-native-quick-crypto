import { Buffer } from '@craftzdog/react-native-buffer';
import { QuickCrypto } from './QuickCrypto';
import FallbackCrypto from 'crypto-browserify';

// @ts-expect-error Buffer does not match exact same type definition.
global.Buffer = Buffer;

const crypto = { ...FallbackCrypto, ...QuickCrypto };

// for randombytes https://github.com/crypto-browserify/randombytes/blob/master/browser.js#L16
// @ts-expect-error QuickCrypto is missing `subtle` and `randomUUID`
global.crypto = crypto;

module.exports = crypto;
export default crypto;
