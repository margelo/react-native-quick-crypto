/**
 * ChaCha20 and ChaCha20-Poly1305 tests
 *
 * Test vectors from IETF RFC 7539 and draft-irtf-cfrg-chacha20-poly1305-03
 * @see https://github.com/calvinmetcalf/chacha20poly1305/blob/master/test/chacha20.js
 * @see https://datatracker.ietf.org/doc/html/rfc7539
 */

import { Buffer } from '@craftzdog/react-native-buffer';
import { createCipheriv } from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';
import { roundTrip, roundTripAuth } from './roundTrip';

const SUITE = 'cipher';

function fromHex(h: string | Buffer): Buffer {
  if (typeof h === 'string') {
    h = h.replace(/([^0-9a-f])/g, '');
    return Buffer.from(h, 'hex');
  }
  return h;
}

interface ChaCha20TestVector {
  key: string;
  nonce: string;
  counter?: number;
  plaintext?: string;
  expected: string;
}

interface ChaCha20Poly1305TestVector {
  key: string;
  nonce: string;
  plaintext: string;
  aad: string | Buffer;
  tag: string;
  expected: string;
}

// Test vectors from RFC 7539 and other sources
const testVectors = {
  rfc7539_vector1: {
    key: '00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f',
    nonce: '00:00:00:00:00:00:00:4a:00:00:00:00',
    counter: 1,
    plaintext:
      // Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.
      '4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c' +
      '65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73' +
      '73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63' +
      '6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f' +
      '6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20' +
      '74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73' +
      '63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69' +
      '74 2e',
    expected:
      '6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81' +
      'e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b' +
      'f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57' +
      '16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8' +
      '07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e' +
      '52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36' +
      '5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42' +
      '87 4d',
  } as ChaCha20TestVector,
  rfc7539_vector2: {
    key:
      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
    nonce: '00 00 00 00 00 00 00 00 00 00 00 00',
    counter: 0,
    plaintext:
      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
    expected:
      '76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28' +
      'bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7' +
      'da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37' +
      '6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86',
  } as ChaCha20TestVector,
  rfc7539_vector3: {
    key:
      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ' +
      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01',
    nonce: '00 00 00 00 00 00 00 00 00 00 00 00',
    plaintext:
      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
    expected:
      '45 40 f0 5a 9f 1f b2 96 d7 73 6e 7b 20 8e 3c 96 ' +
      'eb 4f e1 83 46 88 d2 60 4f 45 09 52 ed 43 2d 41 ' +
      'bb e2 a0 b6 ea 75 66 d2 a5 d1 e7 e2 0d 42 af 2c ' +
      '53 d7 92 b1 c4 3f ea 81 7e 9a d2 75 ae 54 69 63',
  } as ChaCha20TestVector,
  poly1305_vector1: {
    key:
      '80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f ' +
      '90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f',
    nonce: '07 00 00 00 40 41 42 43 44 45 46 47',
    plaintext:
      '4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c' +
      '65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73' +
      '73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63' +
      '6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f' +
      '6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20' +
      '74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73' +
      '63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69' +
      '74 2e',
    aad: '50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7',
    expected:
      'd3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2 ' +
      'a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6 ' +
      '3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b ' +
      '1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36 ' +
      '92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58 ' +
      'fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc ' +
      '3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b' +
      '61 16',
    tag: '1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91',
  } as ChaCha20Poly1305TestVector,
  poly1305_vector2: {
    key:
      'bb 63 42 cb 4f bb 91 69 84 4e b9 bc d1 d1 ab c3 ' +
      '9b ea 97 d4 d6 e5 ff 43 95 0c 81 d3 1d 50 bd 52',
    nonce: '85 b7 2e 32 dc 35 79 3a b9 f1 bb d4',
    plaintext:
      '7b 22 6d 6e 65 6d 6f 6e 69 63 22 3a 22 61 73 6b ' +
      '20 66 72 6f 77 6e 20 62 75 74 74 65 72 20 61 73 ' +
      '74 68 6d 61 20 73 6f 63 69 61 6c 20 61 74 74 69 ' +
      '74 75 64 65 20 6c 6f 6e 67 20 64 79 6e 61 6d 69 ' +
      '63 20 61 77 66 75 6c 20 6d 61 67 69 63 20 61 74 ' +
      '74 65 6e 64 20 70 6f 6e 64 22 7d',
    aad: Buffer.alloc(0),
    expected:
      'f1 25 c4 92 02 4c 5f dd 31 5d 5a e3 f4 88 23 4f ad ' +
      'e3 66 40 17 55 6b 90 90 0d 4f e0 66 48 d5 4e 4f 28 ' +
      '1a 6b 3f 4b 0e 53 f9 bc 12 d2 6f d3 49 62 a2 cf 39 ' +
      'f1 d9 2c 46 c3 7f 34 ac 0d ba ae c6 72 eb 57 05 89 ' +
      '86 ca 35 fc d9 f6 ce f7 5a 3b 1d a9 5f a0 f8 7a 4e ' +
      '0b aa ce f9 77 68',
    tag: 'ca 39 c0 e6 b2 e5 65 2a e0 7f 42 6e b2 dd f3 86',
  } as ChaCha20Poly1305TestVector,
};

function testChaCha20Vector(vector: ChaCha20TestVector, description: string) {
  test(SUITE, `chacha20 ${description}`, () => {
    const key = fromHex(vector.key);
    const originalNonce = fromHex(vector.nonce);
    const plaintext = fromHex(vector.plaintext || '00');
    const expected = fromHex(vector.expected);

    // For OpenSSL ChaCha20, we need to construct a 128-bit IV:
    // [64-bit counter (little-endian)] + [64-bit nonce]
    const counter = vector.counter || 0;
    const iv = Buffer.alloc(16); // 128 bits

    // Write counter as little-endian 64-bit integer in first 8 bytes
    iv.writeUInt32LE(counter, 0);
    iv.writeUInt32LE(0, 4); // High 32 bits of counter

    // Copy the last 8 bytes of the original nonce to complete the IV
    // RFC 7539 nonce is 12 bytes, we need the last 8 bytes
    originalNonce.copy(iv, 8, 4, 12);

    roundTrip('chacha20', key, iv, plaintext);

    const cipher = createCipheriv('chacha20', key, iv);
    const actual = Buffer.concat([cipher.update(plaintext), cipher.final()]);

    expect(actual).to.deep.equal(expected);
  });
}

testChaCha20Vector(testVectors.rfc7539_vector1, 'rfc7539 test vector 1');
testChaCha20Vector(testVectors.rfc7539_vector2, 'rfc7539 test vector 2');
testChaCha20Vector(testVectors.rfc7539_vector3, 'rfc7539 test vector 3');

function testChaCha20Poly1305Vector(
  vector: ChaCha20Poly1305TestVector,
  description: string,
) {
  test(SUITE, `chacha20-poly1305 ${description}`, () => {
    const key = fromHex(vector.key);
    const nonce = fromHex(vector.nonce);
    const plaintext = fromHex(vector.plaintext);
    const aad = fromHex(vector.aad);
    const expectedCiphertext = fromHex(vector.expected);
    const expectedTag = fromHex(vector.tag);

    // First test round trip
    roundTripAuth('chacha20-poly1305', key, nonce, plaintext, aad);

    // Then test against expected values
    const cipher = createCipheriv('chacha20-poly1305', key, nonce);
    cipher.setAAD(aad);
    const actualCipherText = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);

    expect(actualCipherText).to.deep.equal(expectedCiphertext);

    const actualTag = cipher.getAuthTag();
    expect(actualTag).to.deep.equal(expectedTag);
  });
}

testChaCha20Poly1305Vector(
  testVectors.poly1305_vector1,
  'rfc7539 test vector 1',
);
testChaCha20Poly1305Vector(
  testVectors.poly1305_vector2,
  'rfc7539 test vector 2',
);

// // Additional ChaCha20-Poly1305 test vectors with different scenarios
// test(SUITE, 'chacha20-poly1305 empty plaintext', () => {
//   const key = Buffer.from(
//     '0000000000000000000000000000000000000000000000000000000000000000',
//     'hex',
//   );
//   const nonce = Buffer.from('000000000000000000000000', 'hex');
//   const plaintext = Buffer.alloc(0);
//   const aad = Buffer.from('00000000000000000000000000000000', 'hex');

//   roundTripAuth('chacha20-poly1305', key, nonce, plaintext, aad);
// });

// test(SUITE, 'chacha20-poly1305 no aad', () => {
//   const key = Buffer.from(
//     '0000000000000000000000000000000000000000000000000000000000000000',
//     'hex',
//   );
//   const nonce = Buffer.from('000000000000000000000000', 'hex');
//   const plaintext = Buffer.from('00000000000000000000000000000000', 'hex');

//   roundTripAuth('chacha20-poly1305', key, nonce, plaintext);
// });

// test(SUITE, 'chacha20-poly1305 large plaintext', () => {
//   const key = Buffer.from(
//     '0000000000000000000000000000000000000000000000000000000000000000',
//     'hex',
//   );
//   const nonce = Buffer.from('000000000000000000000000', 'hex');
//   const plaintext = Buffer.alloc(1024, 0x42); // 1KB of 0x42
//   const aad = Buffer.from('additional authenticated data', 'utf8');

//   roundTripAuth('chacha20-poly1305', key, nonce, plaintext, aad);
// });

// // Test different tag lengths for ChaCha20-Poly1305
// test(SUITE, 'chacha20-poly1305 custom tag length', () => {
//   const key = Buffer.from(
//     '0000000000000000000000000000000000000000000000000000000000000000',
//     'hex',
//   );
//   const nonce = Buffer.from('000000000000000000000000', 'hex');
//   const plaintext = Buffer.from('Hello, ChaCha20-Poly1305!', 'utf8');
//   const aad = Buffer.from('test aad', 'utf8');

//   // Test with 12-byte tag
//   roundTripAuth('chacha20-poly1305', key, nonce, plaintext, aad, 12);

//   // Test with 8-byte tag
//   roundTripAuth('chacha20-poly1305', key, nonce, plaintext, aad, 8);
// });

// // ChaCha20 edge cases
// test(SUITE, 'chacha20 empty plaintext', () => {
//   const key = Buffer.from(
//     '0000000000000000000000000000000000000000000000000000000000000000',
//     'hex',
//   );
//   const nonce = Buffer.from('000000000000000000000000', 'hex');
//   const plaintext = Buffer.alloc(0);

//   roundTrip('chacha20', key, nonce, plaintext);
// });

// test(SUITE, 'chacha20 single byte', () => {
//   const key = Buffer.from(
//     '0000000000000000000000000000000000000000000000000000000000000000',
//     'hex',
//   );
//   const nonce = Buffer.from('000000000000000000000000', 'hex');
//   const plaintext = Buffer.from([0x42]);

//   roundTrip('chacha20', key, nonce, plaintext);
// });

// test(SUITE, 'chacha20 large plaintext', () => {
//   const key = Buffer.from(
//     '0000000000000000000000000000000000000000000000000000000000000000',
//     'hex',
//   );
//   const nonce = Buffer.from('000000000000000000000000', 'hex');
//   const plaintext = Buffer.alloc(4096, 0x55); // 4KB of 0x55

//   roundTrip('chacha20', key, nonce, plaintext);
// });

// // Test with different nonce formats (96-bit vs 64-bit + counter)
// test(SUITE, 'chacha20 different nonce sizes', () => {
//   const key = Buffer.from(
//     '0000000000000000000000000000000000000000000000000000000000000000',
//     'hex',
//   );
//   const plaintext = Buffer.from('test message', 'utf8');

//   // 96-bit nonce (IETF ChaCha20)
//   const nonce96 = Buffer.from('000000000000000000000000', 'hex');
//   roundTrip('chacha20', key, nonce96, plaintext);

//   // 64-bit nonce (original ChaCha20) - if supported
//   try {
//     const nonce64 = Buffer.from('0000000000000000', 'hex');
//     roundTrip('chacha20', key, nonce64, plaintext);
//   } catch {
//     // Some implementations only support 96-bit nonces
//     console.log('64-bit nonce not supported, skipping');
//   }
// });
