import chai from 'chai';
// import { PrivateKey } from 'sscrypto/node';
// import { Buffer } from '@craftzdog/react-native-buffer';
import { it } from '../../MochaRNAdapter';
import { QuickCrypto as crypto } from 'react-native-quick-crypto';
// const crypto = require('crypto');

// TODO(osp) in order to test publicEncrypt/decrypt generation of RSA KeyPairs is necessary
// this is however yet a lot more work on top of the existing codebase
// and we are trying to cover SSCrypto only (for now), so SSCrypto is used here
// internally it calls publicEncrypt/privateEncrypt but it takes over KeyPair generation
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

  it('generateKeyPair', (done) => {
    crypto.generateKeyPair(
      'rsa',
      {
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
      },
      (err, publicKey, privateKey) => {
        console.warn(err, publicKey, privateKey);
        chai.expect(true).to.equal(true);
        done();
      }
    );
  });
}
