/**
 * XChaCha20-Poly1305 tests
 *
 * Test vectors from IETF draft-irtf-cfrg-xchacha and libsodium test suite.
 * XChaCha20-Poly1305 is an AEAD cipher with:
 * - 32-byte key
 * - 24-byte nonce (extended nonce)
 * - 16-byte authentication tag
 * - AAD (Additional Authenticated Data) support
 */

import {
  Buffer,
  createCipheriv,
  createDecipheriv,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';
import { roundTripAuth } from './roundTrip';

const SUITE = 'cipher';

function fromHex(h: string | Buffer): Buffer {
  if (typeof h === 'string') {
    h = h.replace(/([^0-9a-f])/gi, '');
    return Buffer.from(h, 'hex');
  }
  return h;
}

interface XChaCha20Poly1305TestVector {
  key: string;
  nonce: string;
  plaintext: string;
  aad: string | Buffer;
  ciphertext: string;
  tag: string;
}

// Test vector from IETF draft-irtf-cfrg-xchacha (Appendix A.3.1)
const testVectors: Record<string, XChaCha20Poly1305TestVector> = {
  ietf_a3_1: {
    key: '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
    nonce: '404142434445464748494a4b4c4d4e4f5051525354555657',
    plaintext:
      '4c616469657320616e642047656e746c656d656e206f662074686520636c6173' +
      '73206f66202739393a204966204920636f756c64206f6666657220796f75206f' +
      '6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73' +
      '637265656e20776f756c642062652069742e',
    aad: '50515253c0c1c2c3c4c5c6c7',
    ciphertext:
      'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb' +
      '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452' +
      '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9' +
      '21f9664c97637da9768812f615c68b13b52e',
    tag: 'c0875924c1c7987947deafd8780acf49',
  },
};

function testXChaCha20Poly1305Vector(
  vector: XChaCha20Poly1305TestVector,
  description: string,
) {
  test(SUITE, `xchacha20-poly1305 ${description}`, () => {
    const key = fromHex(vector.key);
    const nonce = fromHex(vector.nonce);
    const plaintext = fromHex(vector.plaintext);
    const aad = fromHex(vector.aad);
    const expectedCiphertext = fromHex(vector.ciphertext);
    const expectedTag = fromHex(vector.tag);

    // First test round trip
    roundTripAuth('xchacha20-poly1305', key, nonce, plaintext, aad);

    // Then test against expected values
    const cipher = createCipheriv('xchacha20-poly1305', key, nonce);
    cipher.setAAD(aad);
    const actualCiphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);
    const actualTag = cipher.getAuthTag();

    expect(actualCiphertext).to.deep.equal(expectedCiphertext);
    expect(actualTag).to.deep.equal(expectedTag);
  });
}

testXChaCha20Poly1305Vector(testVectors.ietf_a3_1!, 'IETF draft A.3.1 vector');

// Basic round-trip tests
test(SUITE, 'xchacha20-poly1305 basic round trip', () => {
  const key = Buffer.alloc(32, 0x42);
  const nonce = Buffer.alloc(24, 0x24);
  const plaintext = Buffer.from('Hello, XChaCha20-Poly1305!', 'utf8');
  const aad = Buffer.from('additional data', 'utf8');

  roundTripAuth('xchacha20-poly1305', key, nonce, plaintext, aad);
});

test(SUITE, 'xchacha20-poly1305 without AAD', () => {
  const key = Buffer.alloc(32, 0x42);
  const nonce = Buffer.alloc(24, 0x24);
  const plaintext = Buffer.from('Hello, XChaCha20-Poly1305!', 'utf8');

  roundTripAuth('xchacha20-poly1305', key, nonce, plaintext);
});

test(SUITE, 'xchacha20-poly1305 empty plaintext', () => {
  const key = Buffer.alloc(32, 0x42);
  const nonce = Buffer.alloc(24, 0x24);
  const plaintext = Buffer.alloc(0);
  const aad = Buffer.from('aad only', 'utf8');

  roundTripAuth('xchacha20-poly1305', key, nonce, plaintext, aad);
});

test(SUITE, 'xchacha20-poly1305 large plaintext', () => {
  const key = Buffer.alloc(32, 0x42);
  const nonce = Buffer.alloc(24, 0x24);
  const plaintext = Buffer.alloc(4096, 0x55);
  const aad = Buffer.from('large data test', 'utf8');

  roundTripAuth('xchacha20-poly1305', key, nonce, plaintext, aad);
});

// Error case tests
test(SUITE, 'xchacha20-poly1305 wrong key size throws', () => {
  const key = Buffer.alloc(16, 0x42); // Wrong size: should be 32
  const nonce = Buffer.alloc(24, 0x24);

  expect(() => {
    createCipheriv('xchacha20-poly1305', key, nonce);
  }).to.throw(/key must be 32 bytes/i);
});

test(SUITE, 'xchacha20-poly1305 wrong nonce size throws', () => {
  const key = Buffer.alloc(32, 0x42);
  const nonce = Buffer.alloc(12, 0x24); // Wrong size: should be 24

  expect(() => {
    createCipheriv('xchacha20-poly1305', key, nonce);
  }).to.throw(/nonce must be 24 bytes/i);
});

test(SUITE, 'xchacha20-poly1305 tag mismatch throws', () => {
  const key = Buffer.alloc(32, 0x42);
  const nonce = Buffer.alloc(24, 0x24);
  const plaintext = Buffer.from('test message', 'utf8');

  // Encrypt
  const cipher = createCipheriv('xchacha20-poly1305', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  // Try to decrypt with wrong tag
  const decipher = createDecipheriv('xchacha20-poly1305', key, nonce);
  const wrongTag = Buffer.alloc(16, 0xff); // Wrong tag
  decipher.setAuthTag(wrongTag);
  decipher.update(ciphertext);

  expect(() => {
    decipher.final();
  }).to.throw(/authentication tag mismatch/i);
});
