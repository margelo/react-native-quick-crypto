/**
 * XSalsa20-Poly1305 tests
 *
 * XSalsa20-Poly1305 is an authenticated cipher (secretbox) with:
 * - 32-byte key
 * - 24-byte nonce (extended nonce)
 * - 16-byte authentication tag
 * - NO AAD support (unlike XChaCha20-Poly1305)
 *
 * This is the authenticated version of the existing XSalsa20 stream cipher.
 */

import {
  Buffer,
  createCipheriv,
  createDecipheriv,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';

const SUITE = 'cipher';

// Helper for XSalsa20-Poly1305 round trip (no AAD support)
function roundTripXSalsa20Poly1305(
  key: Buffer,
  nonce: Buffer,
  plaintext: Buffer,
) {
  // Encrypt
  const cipher = createCipheriv('xsalsa20-poly1305', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Decrypt
  const decipher = createDecipheriv('xsalsa20-poly1305', key, nonce);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  expect(decrypted).to.deep.equal(plaintext);
}

// Basic round-trip tests
test(SUITE, 'xsalsa20-poly1305 basic round trip', () => {
  const key = Buffer.alloc(32, 0x42);
  const nonce = Buffer.alloc(24, 0x24);
  const plaintext = Buffer.from('Hello, XSalsa20-Poly1305!', 'utf8');

  roundTripXSalsa20Poly1305(key, nonce, plaintext);
});

test(SUITE, 'xsalsa20-poly1305 empty plaintext', () => {
  const key = Buffer.alloc(32, 0x42);
  const nonce = Buffer.alloc(24, 0x24);
  const plaintext = Buffer.alloc(0);

  roundTripXSalsa20Poly1305(key, nonce, plaintext);
});

test(SUITE, 'xsalsa20-poly1305 large plaintext', () => {
  const key = Buffer.alloc(32, 0x42);
  const nonce = Buffer.alloc(24, 0x24);
  const plaintext = Buffer.alloc(4096, 0x55);

  roundTripXSalsa20Poly1305(key, nonce, plaintext);
});

test(SUITE, 'xsalsa20-poly1305 single byte', () => {
  const key = Buffer.alloc(32, 0x42);
  const nonce = Buffer.alloc(24, 0x24);
  const plaintext = Buffer.from([0x42]);

  roundTripXSalsa20Poly1305(key, nonce, plaintext);
});

// Test with known test vector from libsodium
test(SUITE, 'xsalsa20-poly1305 test vector', () => {
  // Test vector derived from libsodium secretbox tests
  const key = Buffer.from(
    '1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389',
    'hex',
  );
  const nonce = Buffer.from(
    '69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37',
    'hex',
  );
  const plaintext = Buffer.from(
    'be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5e' +
      'cbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8' +
      '250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb4' +
      '8f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705',
    'hex',
  );

  // Round trip test
  roundTripXSalsa20Poly1305(key, nonce, plaintext);
});

// Error case tests
test(SUITE, 'xsalsa20-poly1305 wrong key size throws', () => {
  const key = Buffer.alloc(16, 0x42); // Wrong size: should be 32
  const nonce = Buffer.alloc(24, 0x24);

  expect(() => {
    createCipheriv('xsalsa20-poly1305', key, nonce);
  }).to.throw(/key must be 32 bytes/i);
});

test(SUITE, 'xsalsa20-poly1305 wrong nonce size throws', () => {
  const key = Buffer.alloc(32, 0x42);
  const nonce = Buffer.alloc(12, 0x24); // Wrong size: should be 24

  expect(() => {
    createCipheriv('xsalsa20-poly1305', key, nonce);
  }).to.throw(/nonce must be 24 bytes/i);
});

test(SUITE, 'xsalsa20-poly1305 tag mismatch throws', () => {
  const key = Buffer.alloc(32, 0x42);
  const nonce = Buffer.alloc(24, 0x24);
  const plaintext = Buffer.from('test message', 'utf8');

  // Encrypt
  const cipher = createCipheriv('xsalsa20-poly1305', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  // Try to decrypt with wrong tag
  const decipher = createDecipheriv('xsalsa20-poly1305', key, nonce);
  const wrongTag = Buffer.alloc(16, 0xff); // Wrong tag
  decipher.setAuthTag(wrongTag);
  decipher.update(ciphertext);

  expect(() => {
    decipher.final();
  }).to.throw(/authentication tag mismatch/i);
});

test(SUITE, 'xsalsa20-poly1305 setAAD throws (not supported)', () => {
  const key = Buffer.alloc(32, 0x42);
  const nonce = Buffer.alloc(24, 0x24);
  const aad = Buffer.from('additional data', 'utf8');

  const cipher = createCipheriv('xsalsa20-poly1305', key, nonce);

  expect(() => {
    cipher.setAAD(aad);
  }).to.throw(/AAD.*not supported/i);
});
