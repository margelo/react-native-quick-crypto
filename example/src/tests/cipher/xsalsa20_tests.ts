import { Buffer, randomFillSync, xsalsa20 } from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';

const SUITE = 'cipher';

// --- Constants and Test Data ---
const key32 = Buffer.from(
  'a8a7d6a5d4a3d2a1a09f9e9d9c8b8a89a8a7d6a5d4a3d2a1a09f9e9d9c8b8a89',
  'hex',
);
const plaintext = 'abcdefghijklmnopqrstuvwxyz';
const plaintextBuffer = Buffer.from(plaintext);

// libsodium cipher tests
test(SUITE, 'xsalsa20', () => {
  const key = new Uint8Array(key32);
  const nonce = randomFillSync(new Uint8Array(24));
  const data = new Uint8Array(plaintextBuffer);
  // encrypt
  const ciphertext = xsalsa20(key, nonce, data);
  // decrypt - must use the same nonce as encryption
  const decrypted = xsalsa20(key, nonce, ciphertext);
  // test decrypted == data
  expect(decrypted).eql(data);
});
