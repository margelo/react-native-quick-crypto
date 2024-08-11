import {expect} from 'chai';
import {Buffer} from '@craftzdog/react-native-buffer';
import {describe, it} from '../../MochaRNAdapter';
import crypto from 'react-native-quick-crypto';
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
    const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {
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
    const padding = crypto.constants.RSA_PKCS1_PSS_PADDING;
    const saltLength = crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN;

    const sign = crypto.createSign('SHA256');
    sign.update(textBuffer);
    const signature = sign.sign({
      key: privateKey,
      padding,
      saltLength,
    });

    const verify = crypto.createVerify('SHA256');
    verify.update(textToSign, 'utf-8');
    const matches = verify.verify(
      {
        key: publicKey,
        padding,
        saltLength,
      },
      signature,
    );

    expect(matches).to.equal(true);
  });

  it('ec sign/verify #387', async () => {
    const privateKeyPem = `
-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgaTunuTuxJ0oduU8A
gchLiPEO5p8URkI0YyUlkNMR+8KgCgYIKoZIzj0DAQehRANCAAS2bcRIxh29Yf49
8bnSu4y3bmVDiJjg0SCWD1mHN8DC5gM8uAaTdnz2IYRsvy+UAbqMc8J1xBeQanwV
nkT8PPPD
-----END PRIVATE KEY-----
    `;

    const publicKeyPem = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtm3ESMYdvWH+PfG50ruMt25lQ4iY
4NEglg9ZhzfAwuYDPLgGk3Z89iGEbL8vlAG6jHPCdcQXkGp8FZ5E/Dzzww==
-----END PUBLIC KEY-----
    `;

    const data = Buffer.from(
      'lets try if we can check the crypto fun here',
      'utf8',
    );

    // Do the signing

    const signer = crypto.createSign('sha256');
    signer.update(data);
    const signature = signer.sign({
      key: privateKeyPem,
      format: 'pem',
      type: 'pkcs8',
      dsaEncoding: 'ieee-p1363',
    });

    console.log(signature.toString('base64'));
    console.log('Signature length', signature.length);

    // Do verify

    const verifier = crypto.createVerify('sha256');
    verifier.update(data);
    const success = verifier.verify(
      {
        key: publicKeyPem,
        format: 'pem',
        type: 'spki',
        dsaEncoding: 'ieee-p1363',
      },
      signature,
    );

    expect(success).to.equal(true);
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
