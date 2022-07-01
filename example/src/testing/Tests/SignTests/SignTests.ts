import chai from 'chai';
import { Buffer } from '@craftzdog/react-native-buffer';
import { it } from '../../MochaRNAdapter';
import { QuickCrypto as crypto } from 'react-native-quick-crypto';
import { PrivateKey } from 'sscrypto/node';

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

export function registerSignTests() {
  // We need to monkey patch sscrypto to use all the crypto functions from quick-crypto
  it('basic sign test', async () => {
    const { publicKey, privateKey } = await crypto.generateKeyPairSync('rsa', {
      modulusLength: 1024,
    });
    const textToSign = 'This text should be signed';
    const textBuffer = Buffer.from(textToSign, 'utf-8');
    const sign = crypto.createSign('SHA256');
    sign.update(textBuffer);
    const signature = sign.sign({
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
    });

    chai.expect(signature.toString('utf8')).to.equal(1);
  });
}
