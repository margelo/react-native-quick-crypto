import chai from 'chai';
import { Buffer } from '@craftzdog/react-native-buffer';
import { it } from '../../MochaRNAdapter';
import crypto from 'react-native-quick-crypto';
import { PrivateKey } from 'sscrypto/node';

// Tests that a key pair can be used for encryption / decryption.
function testEncryptDecrypt(publicKey: any, privateKey: any) {
  const message = 'Hello Node.js world!';
  const plaintext = Buffer.from(message, 'utf8');
  for (const key of [publicKey, privateKey]) {
    const ciphertext = crypto.publicEncrypt(key, plaintext);
    const received = crypto.privateDecrypt(privateKey, ciphertext);
    chai.assert.strictEqual(received.toString('utf8'), message);
  }
}

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

export function registerPublicCipherTests() {
  // We need to monkey patch sscrypto to use all the crypto functions from quick-crypto
  it('sscrypto basic test', async () => {
    try {
      const clearText = 'This is clear text';
      const privateKey = await PrivateKey.generate(1024);
      const encrypted = privateKey.encrypt(Buffer.from(clearText) as any);
      const decrypted = privateKey.decrypt(encrypted);
      chai.expect(decrypted.toString('utf-8')).to.equal(clearText);
    } catch (e) {
      console.warn('error', e);
      chai.assert.fail();
    }
  });

  it('publicEncrypt/privateDecrypt', () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 512,
      publicKeyEncoding: {
        type: 'pkcs1',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    testEncryptDecrypt(publicKey, privateKey);
  });

  it('publicEncrypt/privateDecrypt with non-common exponent', () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      publicExponent: 3,
      modulusLength: 512,
      publicKeyEncoding: {
        type: 'pkcs1',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    testEncryptDecrypt(publicKey, privateKey);
  });

  it('publicEncrypt/privateDecrypt with passphrase', () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase: 'top secret',
      },
    });

    const message = 'Hello RN world!';
    const plaintext = Buffer.from(message, 'utf8');
    const ciphertext = crypto.publicEncrypt(publicKey, plaintext);
    const decrypted = crypto.privateDecrypt(
      { key: privateKey, passphrase: 'top secret' },
      ciphertext
    );

    chai.expect(decrypted.toString('utf-8')).to.equal(message);
  });

  it('passphrased private key without passphrase should throw', () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase: 'top secret',
      },
    });

    try {
      testEncryptDecrypt(publicKey, privateKey);
      chai.assert.fail();
    } catch (e) {
      // intentionally left blank
    }
  });
}
