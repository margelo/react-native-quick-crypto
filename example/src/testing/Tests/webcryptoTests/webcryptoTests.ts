import chai from 'chai';
import { atob, btoa } from 'react-native-quick-base64';
import crypto from 'react-native-quick-crypto';
import { it } from '../../MochaRNAdapter';

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

export function webcryptoRegisterTests() {
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
    console.log('spkiKey', spkiKey);
    chai
      .expect(spkiKey)
      .to.equal(
        'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENlFpbMBNfCY6Lhj9A/clefyxJVIXGJ0y6CcZ/cbbyyebvN6T0aNPvpQyFdUwRtYvFHlYbqIZOM8AoqdPcnSMIA=='
      );
  });

  it('PBKDF2 importKey raw/deriveBits', async () => {
    const key = await crypto.subtle.importKey(
      'raw',
      'password',
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: 'salt',
        iterations: 1,
        hash: {
          name: 'SHA-512',
        },
      },
      key,
      // eslint-disable-next-line no-bitwise
      64 << 3
    );
    const pbkdf2Key = arrayBufferToBase64(bits);
    chai
      .expect(pbkdf2Key)
      .to.equal('hn9wzxreAs/zdSWZo6U9xK80x6ZpgVrl1RNVThyM8lLALUcKKFoFAbrZmb/pQ8CPBQI119aLHaVeY/c7YKV/zg==');
  });
}
