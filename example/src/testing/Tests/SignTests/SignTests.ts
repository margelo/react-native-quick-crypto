import { expect } from 'chai';
import { Buffer } from '@craftzdog/react-native-buffer';
import { describe, it } from '../../MochaRNAdapter';
import QuickCrypto from 'react-native-quick-crypto';
// import { PrivateKey } from 'sscrypto/node';

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

describe('sign/verify', () => {
  it('basic sign/verify', async () => {
    const { publicKey, privateKey } = QuickCrypto.generateKeyPairSync('rsa', {
      modulusLength: 1024,
      publicKeyEncoding: {
        type: 'pkcs1',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    const textToSign = 'This text should be signed';
    const textBuffer = Buffer.from(textToSign, 'utf-8');
    const padding = QuickCrypto.constants.RSA_PKCS1_PSS_PADDING;
    const saltLength = QuickCrypto.constants.RSA_PSS_SALTLEN_MAX_SIGN;

    const sign = QuickCrypto.createSign('SHA256');
    sign.update(textBuffer);
    const signature = sign.sign({
      key: privateKey,
      padding,
      saltLength,
    });

    const verify = QuickCrypto.createVerify('SHA256');
    verify.update(textToSign, 'utf-8');
    const matches = verify.verify(
      {
        key: publicKey,
        padding,
        saltLength,
      },
      signature
    );

    expect(matches).to.equal(true);
  });

  // // We need to monkey patch sscrypto to use all the crypto functions from quick-crypto
  // it('simple sscrypto sign/verify', async () => {
  //   const clearText = 'This is clear text';
  //   console.log(0);
  //   const privateKey = await PrivateKey.generate(1024);
  //   console.log(1, privateKey);
  //   const signature = privateKey.sign(Buffer.from(clearText) as any);
  //   console.log(2);
  //   const verified = privateKey.verify(
  //     Buffer.from(clearText) as any,
  //     signature
  //   );
  //   console.log(3);
  //   expect(verified).to.equal(true);
  // });
});
