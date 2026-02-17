import {
  Buffer,
  getCiphers,
  createCipheriv,
  createDecipheriv,
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

// Issue #798: decipher.final() should throw on incorrect key for aes-256-gcm
test(SUITE, 'GCM wrong key throws error (issue #798)', () => {
  const correctKey = Buffer.from('a'.repeat(64), 'hex'); // 32 bytes
  const wrongKey = Buffer.from('b'.repeat(64), 'hex'); // different 32 bytes
  const testIv = randomFillSync(new Uint8Array(12));
  const testPlaintext = Buffer.from('test data for encryption');
  const testAad = Buffer.from('additional data');

  // Encrypt with correct key
  const cipher = createCipheriv('aes-256-gcm', correctKey, Buffer.from(testIv));
  cipher.setAAD(testAad);
  const encrypted = Buffer.concat([
    cipher.update(testPlaintext),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // Decrypt with wrong key - should throw on final()
  const decipher = createDecipheriv(
    'aes-256-gcm',
    wrongKey,
    Buffer.from(testIv),
  );
  decipher.setAAD(testAad);
  decipher.setAuthTag(authTag);
  decipher.update(encrypted);

  expect(() => decipher.final()).to.throw();
});

// --- String encoding tests (issue #945) ---

test(SUITE, 'Buffer concat vs string concat produce same result', () => {
  const testKey = Buffer.from(
    'KTnGEDonslhj/qGvf6rj4HSnO32T7dvjAs5PntTDB0s=',
    'base64',
  );
  const testIv = Buffer.from('2pXx2krk1wU8RI6AQjuPUg==', 'base64');
  const text = 'this is a test.';

  // Buffer concat approach
  const cipher1 = createCipheriv('aes-256-cbc', testKey, testIv);
  const bufResult = Buffer.concat([
    cipher1.update(Buffer.from(text, 'utf8')),
    cipher1.final(),
  ]).toString('base64');

  // String concat approach (fresh cipher)
  const cipher2 = createCipheriv('aes-256-cbc', testKey, testIv);
  const strResult =
    cipher2.update(text, 'utf8', 'base64') + cipher2.final('base64');

  expect(bufResult).to.equal(strResult);
});

test(SUITE, 'base64 string encoding with multi-block plaintext', () => {
  const testKey = Buffer.from(
    'KTnGEDonslhj/qGvf6rj4HSnO32T7dvjAs5PntTDB0s=',
    'base64',
  );
  const testIv = Buffer.from('2pXx2krk1wU8RI6AQjuPUg==', 'base64');
  // 32 bytes = 2 AES blocks; update() returns 32 bytes, 32 % 3 = 2 remainder
  const text = 'A'.repeat(32);

  const cipher1 = createCipheriv('aes-256-cbc', testKey, testIv);
  const bufResult = Buffer.concat([
    cipher1.update(Buffer.from(text, 'utf8')),
    cipher1.final(),
  ]).toString('base64');

  const cipher2 = createCipheriv('aes-256-cbc', testKey, testIv);
  const strResult =
    cipher2.update(text, 'utf8', 'base64') + cipher2.final('base64');

  expect(bufResult).to.equal(strResult);
});

test(SUITE, 'base64 encoding at exactly one block boundary', () => {
  // 16 bytes = exactly one AES block; update() returns 16 bytes, 16 % 3 = 1
  const text = 'A'.repeat(16);

  const cipher1 = createCipheriv('aes-128-cbc', key16, iv);
  const bufResult = Buffer.concat([
    cipher1.update(Buffer.from(text, 'utf8')),
    cipher1.final(),
  ]).toString('base64');

  const cipher2 = createCipheriv('aes-128-cbc', key16, iv);
  const strResult =
    cipher2.update(text, 'utf8', 'base64') + cipher2.final('base64');

  expect(bufResult).to.equal(strResult);
});

test(SUITE, 'base64 encoding encrypt/decrypt roundtrip with long input', () => {
  const longText = 'The quick brown fox jumps over the lazy dog. '.repeat(5);

  const cipher = createCipheriv('aes-256-cbc', key32, iv);
  const encrypted =
    cipher.update(longText, 'utf8', 'base64') + cipher.final('base64');

  const decipher = createDecipheriv('aes-256-cbc', key32, iv);
  const decrypted =
    decipher.update(encrypted, 'base64', 'utf8') + decipher.final('utf8');

  expect(decrypted).to.equal(longText);
});

test(SUITE, 'update with hex input and output encoding', () => {
  const cipher1 = createCipheriv('aes-128-cbc', key16, iv);
  const bufResult = Buffer.concat([
    cipher1.update(plaintextBuffer),
    cipher1.final(),
  ]).toString('hex');

  const cipher2 = createCipheriv('aes-128-cbc', key16, iv);
  const hexResult =
    cipher2.update(plaintext, 'utf8', 'hex') + cipher2.final('hex');

  expect(bufResult).to.equal(hexResult);
});

test(SUITE, 'update with hex input decryption', () => {
  // Encrypt
  const cipher = createCipheriv('aes-128-cbc', key16, iv);
  const encrypted =
    cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');

  // Decrypt using hex input encoding
  const decipher = createDecipheriv('aes-128-cbc', key16, iv);
  const decrypted =
    decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');

  expect(decrypted).to.equal(plaintext);
});

test(SUITE, 'update with hex encoding roundtrip (aes-256-cbc)', () => {
  // Encrypt
  const cipher = createCipheriv('aes-256-cbc', key32, iv);
  const encrypted =
    cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');

  // Decrypt
  const decipher = createDecipheriv('aes-256-cbc', key32, iv);
  const decrypted =
    decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');

  expect(decrypted).to.equal(plaintext);
});

// --- Cipher state violation tests ---

test(SUITE, 'update after final throws', () => {
  const cipher = createCipheriv('aes-128-cbc', key16, iv);
  cipher.update(plaintextBuffer);
  cipher.final();

  expect(() => cipher.update(plaintextBuffer)).to.throw();
});

test(SUITE, 'final called twice throws', () => {
  const cipher = createCipheriv('aes-128-cbc', key16, iv);
  cipher.update(plaintextBuffer);
  cipher.final();

  expect(() => cipher.final()).to.throw();
});

test(SUITE, 'decipher update after final throws', () => {
  // First encrypt something
  const cipher = createCipheriv('aes-128-cbc', key16, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintextBuffer),
    cipher.final(),
  ]);

  // Decrypt and then try to reuse
  const decipher = createDecipheriv('aes-128-cbc', key16, iv);
  decipher.update(encrypted);
  decipher.final();

  expect(() => decipher.update(encrypted)).to.throw();
});

test(SUITE, 'cipher works after re-init (createCipheriv)', () => {
  // First use
  const cipher1 = createCipheriv('aes-128-cbc', key16, iv);
  const enc1 = Buffer.concat([
    cipher1.update(plaintextBuffer),
    cipher1.final(),
  ]);

  // Second use with same params should produce identical result
  const cipher2 = createCipheriv('aes-128-cbc', key16, iv);
  const enc2 = Buffer.concat([
    cipher2.update(plaintextBuffer),
    cipher2.final(),
  ]);

  expect(enc1.toString('hex')).to.equal(enc2.toString('hex'));

  // Verify decryption still works
  const decipher = createDecipheriv('aes-128-cbc', key16, iv);
  const decrypted = Buffer.concat([decipher.update(enc2), decipher.final()]);
  expect(decrypted.toString('utf8')).to.equal(plaintext);
});

test(SUITE, 'GCM tampered ciphertext throws error', () => {
  const testKey = Buffer.from(randomFillSync(new Uint8Array(32)));
  const testIv = randomFillSync(new Uint8Array(12));
  const testPlaintext = Buffer.from('test data');
  const testAad = Buffer.from('additional data');

  const cipher = createCipheriv('aes-256-gcm', testKey, Buffer.from(testIv));
  cipher.setAAD(testAad);
  const encrypted = Buffer.concat([
    cipher.update(testPlaintext),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // Tamper with ciphertext
  encrypted[0] = encrypted[0]! ^ 1;

  const decipher = createDecipheriv(
    'aes-256-gcm',
    testKey,
    Buffer.from(testIv),
  );
  decipher.setAAD(testAad);
  decipher.setAuthTag(authTag);
  decipher.update(encrypted);

  expect(() => decipher.final()).to.throw();
});

test(SUITE, 'GCM tampered auth tag throws error', () => {
  const testKey = Buffer.from(randomFillSync(new Uint8Array(32)));
  const testIv = randomFillSync(new Uint8Array(12));
  const testPlaintext = Buffer.from('test data');
  const testAad = Buffer.from('additional data');

  const cipher = createCipheriv('aes-256-gcm', testKey, Buffer.from(testIv));
  cipher.setAAD(testAad);
  const encrypted = Buffer.concat([
    cipher.update(testPlaintext),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // Tamper with auth tag
  authTag[0] = authTag[0]! ^ 1;

  const decipher = createDecipheriv(
    'aes-256-gcm',
    testKey,
    Buffer.from(testIv),
  );
  decipher.setAAD(testAad);
  decipher.setAuthTag(authTag);
  decipher.update(encrypted);

  expect(() => decipher.final()).to.throw();
});
