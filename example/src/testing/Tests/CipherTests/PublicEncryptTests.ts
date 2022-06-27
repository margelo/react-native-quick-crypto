import chai from 'chai';
import { Buffer } from '@craftzdog/react-native-buffer';
import { it } from '../../MochaRNAdapter';
import { QuickCrypto as crypto } from 'react-native-quick-crypto';
// const crypto = require('crypto');

// function testEncryptDecrypt(publicKey: any, privateKey: any) {
//   const message = 'Hello Node.js world!';
//   const plaintext = Buffer.from(message, 'utf8');
//   for (const key of [publicKey, privateKey]) {
//     const ciphertext = crypto.publicEncrypt(key, plaintext);
//     console.warn('cipher text', ciphertext);
//     // const received = crypto.privateDecrypt(privateKey, ciphertext);
//     // assert.strictEqual(received.toString('utf8'), message);
//   }
// }

export function registerPublicEncryptTests() {
  // it('sscrypto basic test', async () => {
  //   // crypto.publicEncrypt(
  //   //   {
  //   //     key: 'test',
  //   //     padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
  //   //   },
  //   //   'cleartext'
  //   // );
  //   // const keyBuffer = Buffer.from('myKey');
  //   // console.warn('isBuffer', keyBuffer.);
  //   console.warn('mk1');
  //   // const key = new PublicKey(keyBuffer as any);
  //   try {
  //     const privateKey = await PrivateKey.generate(1024);
  //     console.warn('mk2');
  //     const encrypted = privateKey.encrypt(
  //       Buffer.from('This is clear text') as any
  //     );
  //     console.log('encrypted', encrypted);
  //     chai.expect(true).to.equal(true);
  //   } catch (e) {
  //     console.warn('error', e);
  //   }
  // });

  it('basic encrypt/decrypt', () => {
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

    // testEncryptDecrypt(publicKey, privateKey);
    const message = 'Hello RN world!';
    const plaintext = Buffer.from(message, 'utf8');
    const ciphertext = crypto.publicEncrypt(publicKey, plaintext);
    console.warn('ciphertext', ciphertext);
  });
}
