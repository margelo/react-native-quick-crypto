import { assert, expect } from 'chai';
import { Buffer } from '@craftzdog/react-native-buffer';
import { describe, it } from '../../MochaRNAdapter';
import crypto from 'react-native-quick-crypto';
import type { KeyPairKey } from '../../../../../src/Cipher';
import type { EncodingOptions } from '../../../../../src/keys';
// import { PrivateKey } from 'sscrypto/node';

// Tests that a key pair can be used for encryption / decryption.
function testEncryptDecrypt(publicKey: KeyPairKey, privateKey: KeyPairKey) {
  const message = 'Hello Node.js world!';
  const plaintext = Buffer.from(message, 'utf8');
  for (const key of [publicKey, privateKey]) {
    // the EncodingOptions type is weird as shit, but it works.
    // Someone else is welcome to wade through rsaFunctionFor and figure out a
    // better way.
    const ciphertext = crypto.publicEncrypt(key as EncodingOptions, plaintext);
    const received = crypto.privateDecrypt(
      privateKey as EncodingOptions,
      ciphertext,
    );
    assert.strictEqual(received.toString('utf8'), message);
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

describe('publicCipher', () => {
  // // We need to monkey patch sscrypto to use all the crypto functions from quick-crypto
  // it('sscrypto basic test', async () => {
  //   try {
  //     const clearText = 'This is clear text';
  //     const privateKey = await PrivateKey.generate(1024);
  //     const encrypted = privateKey.encrypt(Buffer.from(clearText) as any);
  //     const decrypted = privateKey.decrypt(encrypted);
  //     expect(decrypted.toString('utf-8')).to.equal(clearText);
  //   } catch (e) {
  //     assert.fail();
  //   }
  // });

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
    const ciphertext = crypto.publicEncrypt(
      publicKey as EncodingOptions,
      plaintext,
    );
    const decrypted = crypto.privateDecrypt(
      { key: privateKey, passphrase: 'top secret' },
      ciphertext,
    );

    expect(decrypted.toString('utf-8')).to.equal(message);
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
      assert.fail();
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (_e) {
      // intentionally left blank
    }
  });
});
