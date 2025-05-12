// react-native-quick-crypto is polyfilled in this example app, so jose will use it
import { CompactEncrypt, exportJWK, importJWK } from 'jose';
import type { KeyObject } from 'jose';
import { describe, it } from '../../MochaRNAdapter';
import crypto from 'react-native-quick-crypto';

describe('jose compatibility', () => {
  it('importJWK', async () => {
    const key = {
      kty: 'RSA',
      use: 'enc',
      alg: 'RSA-OAEP-256',
      n: 'n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw',
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
