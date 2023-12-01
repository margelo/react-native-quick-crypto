import { Buffer } from '@craftzdog/react-native-buffer';
import chai from 'chai';
import crypto from 'react-native-quick-crypto';
import { describe, it } from '../../MochaRNAdapter';
import { atob } from 'react-native-quick-base64';

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

    crypto.subtle.exportKey('spki', key);

    chai.expect(1).to.equal(2);
  });
}
