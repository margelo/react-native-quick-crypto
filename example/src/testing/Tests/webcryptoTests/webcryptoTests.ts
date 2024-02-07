import { expect } from 'chai';
import { atob, btoa } from 'react-native-quick-base64';
import crypto from 'react-native-quick-crypto';
import { describe, it } from '../../MochaRNAdapter';
import type { HashAlgorithm } from '../../../../../src/keys';

// Tests that a key pair can be used for encryption / decryption.
// function testEncryptDecrypt(publicKey: any, privateKey: any) {
//   const message = 'Hello Node.js world!';
//   const plaintext = Buffer.from(message, 'utf8');
//   for (const key of [publicKey, privateKey]) {
//     const ciphertext = crypto.publicEncrypt(key, plaintext);
//     const received = crypto.privateDecrypt(privateKey, ciphertext);
//     chai.assert.strictEqual(received.toString('utf8'), message);
//   }
// }

// I guess interally this functions use privateEncrypt/publicDecrypt (sign/verify)
// but the main function `sign` is not implemented yet
// Tests that a key pair can be used for signing / verification.
// function testSignVerify(publicKey: any, privateKey: any) {
//   const message = Buffer.from('Hello Node.js world!');

//   function oldSign(algo, data, key) {
//     return createSign(algo).update(data).sign(key);
//   }

//   function oldVerify(algo, data, key, signature) {
//     return createVerify(algo).update(data).verify(key, signature);
//   }

//   for (const signFn of [sign, oldSign]) {
//     const signature = signFn('SHA256', message, privateKey);
//     for (const verifyFn of [verify, oldVerify]) {
//       for (const key of [publicKey, privateKey]) {
//         const okay = verifyFn('SHA256', message, key, signature);
//         assert(okay);
//       }
//     }
//   }
// }

type TestFixture = [
  string,
  string,
  number,
  HashAlgorithm | string,
  number,
  string
];

function base64ToArrayBuffer(val: string): ArrayBuffer {
  var binaryString = atob(val);
  var bytes = new Uint8Array(binaryString.length);
  for (var i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

function arrayBufferToBase64(buffer: ArrayBuffer) {
  var binary = '';
  var bytes = new Uint8Array(buffer);
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

function ab2str(buf: ArrayBuffer) {
  return Buffer.from(buf).toString('hex');
}

describe('webcrypto', () => {
  it('EC import raw/export SPKI', async () => {
    const key = await crypto.subtle.importKey(
      'raw',
      base64ToArrayBuffer(
        'BDZRaWzATXwmOi4Y/QP3JXn8sSVSFxidMugnGf3G28snm7zek9GjT76UMhXVMEbWLxR5WG6iGTjPAKKnT3J0jCA='
      ),
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    );

    const buf = await crypto.subtle.exportKey('spki', key);
    const spkiKey = arrayBufferToBase64(buf);
    expect(spkiKey).to.equal(
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENlFpbMBNfCY6Lhj9A/clefyxJVIXGJ0y6CcZ/cbbyyebvN6T0aNPvpQyFdUwRtYvFHlYbqIZOM8AoqdPcnSMIA=='
    );
  });

  // PBKDF2 deriveBits()
  {
    const test = async (
      pass: string,
      salt: string,
      iterations: number,
      hash: HashAlgorithm | string,
      length: number,
      expected: string
    ) => {
      const key = await crypto.subtle.importKey(
        'raw',
        pass,
        { name: 'PBKDF2', hash },
        false,
        ['deriveBits']
      );

      const bits = await crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt,
          iterations,
          hash,
        },
        key,
        length
      );
      const pbkdf2Key = ab2str(bits);
      expect(pbkdf2Key).to.equal(expected);
    };

    const kTests: TestFixture[] = [
      [
        'hello',
        'there',
        10,
        'SHA-256',
        512,
        'f72d1cf4853fffbd16a42751765d11f8dc7939498ee7b7' +
          'ce7678b4cb16fad88098110a83e71f4483ce73203f7a64' +
          '719d293280f780f9fafdcf46925c5c0588b3',
      ],
      ['hello', 'there', 5, 'SHA-384', 128, '201509b012c9cd2fbe7ea938f0c509b3'],
    ];

    kTests.forEach(async ([pass, salt, iterations, hash, length, expected]) => {
      it(`PBKDF2 importKey raw/deriveBits - ${pass} ${salt} ${iterations} ${hash} ${length}`, async () => {
        await test(pass, salt, iterations, hash, length, expected);
      });
    });
  }
});
