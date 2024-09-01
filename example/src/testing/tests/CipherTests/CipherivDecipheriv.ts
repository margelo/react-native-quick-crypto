// copied from https://github.com/nodejs/node/blob/master/test/parallel/test-crypto-hash.js
import crypto from 'react-native-quick-crypto';
import { describe, it } from '../../MochaRNAdapter';
import { assert } from 'chai';
import { Buffer } from '@craftzdog/react-native-buffer';

describe('createCipheriv/createDecipheriv', () => {
  'use strict';

  function testCipher1(key: string | Buffer, iv: string | Buffer) {
    it('testCipher1 + ' + key + ' + ' + iv, () => {
      // Test encryption and decryption with explicit key and iv
      const plaintext =
        '32|RmVZZkFUVmpRRkp0TmJaUm56ZU9qcnJkaXNNWVNpTTU*|iXmckfRWZBGWWELw' +
        'eCBsThSsfUHLeRe0KCsK8ooHgxie0zOINpXxfZi/oNG7uq9JWFVCk70gfzQH8ZUJ' +
        'jAfaFg**';
      const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);
      let ciph = cipher.update(plaintext, 'utf8', 'hex') as string;
      ciph += cipher.final('hex');

      const decipher = crypto.createDecipheriv('des-ede3-cbc', key, iv);
      let txt = decipher.update(ciph, 'hex', 'utf8') as string;
      txt += decipher.final('utf8');

      assert.strictEqual(
        txt,
        plaintext,
        `encryption/decryption with key ${key} and iv ${iv}`,
      );

      // Streaming cipher interface
      // NB: In real life, it's not guaranteed that you can get all of it
      // in a single read() like this.  But in this case, we know it's
      // quite small, so there's no harm.
      const cStream = crypto.createCipheriv('des-ede3-cbc', key, iv);
      cStream.end(plaintext);
      ciph = cStream.read();

      const dStream = crypto.createDecipheriv('des-ede3-cbc', key, iv);
      dStream.end(ciph);
      txt = dStream.read().toString('utf8');

      assert.strictEqual(
        txt,
        plaintext,
        `streaming cipher with key ${key} and iv ${iv}`,
      );
    });
  }

  function testCipher2(key: string | Buffer, iv: string | Buffer) {
    it('testCipher2 + ' + key + ' + ' + iv, () => {
      // Test encryption and decryption with explicit key and iv
      const plaintext =
        '32|RmVZZkFUVmpRRkp0TmJaUm56ZU9qcnJkaXNNWVNpTTU*|iXmckfRWZBGWWELw' +
        'eCBsThSsfUHLeRe0KCsK8ooHgxie0zOINpXxfZi/oNG7uq9JWFVCk70gfzQH8ZUJ' +
        'jAfaFg**';
      const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);
      let ciph = cipher.update(plaintext, 'utf8', 'buffer') as Uint8Array;
      ciph = Buffer.concat([ciph, cipher.final('buffer') as Uint8Array]);

      const decipher = crypto.createDecipheriv('des-ede3-cbc', key, iv);
      let txt = decipher.update(ciph, 'buffer', 'utf8');
      txt += decipher.final('utf8') as string;

      assert.strictEqual(
        txt,
        plaintext,
        `encryption/decryption with key ${key} and iv ${iv}`,
      );
    });
  }

  function testAESGCM(key: Buffer, iv: Buffer) {
    const plaintext = 'Hello, world!';

    it('AES-GCM with key and iv - default AuthTag length', async () => {
      const defaultCipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      defaultCipher.update(plaintext, 'utf8', 'hex');
      defaultCipher.final('hex');
      const defaultAuthTag = defaultCipher.getAuthTag();
      assert.strictEqual(Buffer.from(defaultAuthTag).length, 16);
    });

    it('AES-GCM with key and iv ', () => {
      // Encryption
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, {
        // using an uncommon auth tag length for corner case checking. default is usually 16.
        authTagLength: 4,
      });
      let encrypted = cipher.update(plaintext, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      const authTag = cipher.getAuthTag();
      assert.strictEqual(Buffer.from(authTag).length, 4);

      // Decryption
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, {
        // using an uncommon auth tag length for corner case checking. default is usually 16.
        authTagLength: 4,
      });
      decipher.setAuthTag(Buffer.from(authTag));
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      assert.strictEqual(
        decrypted,
        plaintext,
        'Decrypted text should match the original plaintext',
      );
    });
  }

  testCipher1('0123456789abcd0123456789', '12345678');
  testCipher1('0123456789abcd0123456789', Buffer.from('12345678'));
  testCipher1(Buffer.from('0123456789abcd0123456789'), '12345678');
  testCipher1(Buffer.from('0123456789abcd0123456789'), Buffer.from('12345678'));
  testCipher2(Buffer.from('0123456789abcd0123456789'), Buffer.from('12345678'));

  // Key and IV generation for AES-GCM
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  testAESGCM(key, iv);
});
