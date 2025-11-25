import { Buffer } from '@craftzdog/react-native-buffer';
import {
  getCiphers,
  createCipheriv,
  randomFillSync,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';
import { roundTrip, roundTripAuth } from './roundTrip';

const SUITE = 'cipher';

// --- Constants and Test Data ---
const key16 = Buffer.from('a8a7d6a5d4a3d2a1a09f9e9d9c8b8a89', 'hex');
const key32 = Buffer.from(
  'a8a7d6a5d4a3d2a1a09f9e9d9c8b8a89a8a7d6a5d4a3d2a1a09f9e9d9c8b8a89',
  'hex',
);
const iv16 = randomFillSync(new Uint8Array(16));
const iv12 = randomFillSync(new Uint8Array(12)); // Common IV size for GCM/CCM/OCB
const iv = Buffer.from(iv16);
const aad = Buffer.from('Additional Authenticated Data');
const plaintext = 'abcdefghijklmnopqrstuvwxyz';
const plaintextBuffer = Buffer.from(plaintext);

// --- Tests ---
test(SUITE, 'valid algorithm', () => {
  expect(() => {
    createCipheriv('aes-128-cbc', Buffer.alloc(16), Buffer.alloc(16), {});
  }).to.not.throw();
});

test(SUITE, 'invalid algorithm', () => {
  expect(() => {
    createCipheriv('aes-128-boorad', Buffer.alloc(16), Buffer.alloc(16), {});
  }).to.throw('Unsupported or unknown cipher type: aes-128-boorad');
});

test(SUITE, 'strings', () => {
  // roundtrip expects Buffers, convert strings first
  roundTrip(
    'aes-128-cbc',
    key16.toString('hex'),
    iv.toString('hex'),
    plaintextBuffer,
  );
});

test(SUITE, 'buffers', () => {
  roundTrip('aes-128-cbc', key16, iv, plaintextBuffer);
});

// AES-CBC-HMAC ciphers are TLS-only and require special ctrl functions.
// They also depend on specific hardware (AES-NI) and may not be available
// on all platforms (e.g., CI emulators). Skip them in tests.
// See: https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_cbc_hmac_sha1.html
const TLS_ONLY_CIPHERS = [
  'AES-128-CBC-HMAC-SHA1',
  'AES-128-CBC-HMAC-SHA256',
  'AES-256-CBC-HMAC-SHA1',
  'AES-256-CBC-HMAC-SHA256',
];

// loop through each cipher and test roundtrip
const allCiphers = getCiphers().filter(
  c => !TLS_ONLY_CIPHERS.includes(c.toUpperCase()),
);
allCiphers.forEach(cipherName => {
  test(SUITE, cipherName, () => {
    try {
      // Determine correct key length
      let keyLen = 32; // Default to 256-bit
      if (cipherName.includes('128')) {
        keyLen = 16;
      } else if (cipherName.includes('192')) {
        keyLen = 24;
      }
      let testKey: Uint8Array;
      if (cipherName.includes('XTS')) {
        keyLen *= 2; // XTS requires double length key
        testKey = randomFillSync(new Uint8Array(keyLen));
        const keyBuffer = Buffer.from(testKey); // Create Buffer once
        // Ensure key halves are not identical for XTS
        const half = keyLen / 2;
        while (
          keyBuffer.subarray(0, half).equals(keyBuffer.subarray(half, keyLen))
        ) {
          testKey = randomFillSync(new Uint8Array(keyLen));
          Object.assign(keyBuffer, Buffer.from(testKey));
        }
      } else {
        testKey = randomFillSync(new Uint8Array(keyLen));
      }

      // Select IV size based on mode
      const testIv: Uint8Array =
        cipherName.includes('GCM') ||
        cipherName.includes('OCB') ||
        cipherName.includes('CCM') ||
        cipherName.includes('Poly1305')
          ? iv12
          : iv16;

      // Create key and iv as Buffers for the roundtrip functions
      const key = Buffer.from(testKey);
      const iv = Buffer.from(testIv);

      // Determine if authenticated mode and call appropriate roundtrip helper
      if (
        cipherName.includes('GCM') ||
        cipherName.includes('CCM') ||
        cipherName.includes('OCB') ||
        cipherName.includes('Poly1305') ||
        cipherName.includes('SIV') // SIV modes also use auth
      ) {
        roundTripAuth(cipherName, key, iv, plaintextBuffer, aad);
      } else {
        roundTrip(cipherName, key, iv, plaintextBuffer);
      }
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      expect.fail(`Cipher ${cipherName} threw an error: ${message}`);
    }
  });
});

test(SUITE, 'GCM getAuthTag', () => {
  const cipher = createCipheriv('aes-256-gcm', key32, iv12);
  cipher.setAAD(aad);
  cipher.update(plaintextBuffer);
  cipher.final();

  const tag = cipher.getAuthTag();
  expect(tag.length).to.equal(16);
});
