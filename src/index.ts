import { Buffer } from '@craftzdog/react-native-buffer';
import { QuickCrypto } from './QuickCrypto';

// @ts-expect-error Buffer does not match exact same type definition.
global.Buffer = Buffer;

// @ts-expect-error subtle isn't full implemented and Cryptokey is missing
global.crypto = QuickCrypto;

module.exports = crypto;
export default crypto;
