// react-native-quick-crypto is polyfilled in this example app, so jose will use it
import { CompactEncrypt, exportJWK, importJWK } from 'jose';
import type { KeyObject } from 'jose';
import { describe, it } from '../../MochaRNAdapter';
import crypto from 'react-native-quick-crypto';

describe('jose compatibility', () => {
  it('importJwk', async () => {
    const key = {
      kty: 'RSA',
      use: 'enc',
      alg: 'RSA-OAEP-256',
      n: 'qPfgaTEWEP3S9w0tgsicURfo-nLW09_0KfOPinhYZ4ouzU-3xC4pSlEp8Ut9FgL0AgqNslNaK34Kq-NZjO9DAQ==',
      e: 'AQAB',
    };
    const value = 'hello world';

    const publicKey = await importJWK(key);
    const plaintext = Buffer.from(value, 'utf-8');
    const encryptedValue = await new CompactEncrypt(plaintext)
      .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
      .encrypt(publicKey);

    console.log(encryptedValue);
  });

  it('exportJWK', async () => {
    crypto.generateKeyPair('rsa', { modulusLength: 4096 }, (err, publicKey) => {
      if (err) {
        console.error('internal error', err);
        return;
      }
      const publicKeyJwk = exportJWK(publicKey as KeyObject);
      console.log(publicKeyJwk);
    });
  });
});
