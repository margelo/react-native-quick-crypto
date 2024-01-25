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
      let ciph = cipher.update(plaintext, 'utf8', 'hex');
      ciph += cipher.final('hex');

      const decipher = crypto.createDecipheriv('des-ede3-cbc', key, iv);
      let txt = decipher.update(ciph, 'hex', 'utf8');
      txt += decipher.final('utf8');

      assert.strictEqual(
        txt,
        plaintext,
        `encryption/decryption with key ${key} and iv ${iv}`
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
        `streaming cipher with key ${key} and iv ${iv}`
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
      let ciph = cipher.update(plaintext, 'utf8', 'buffer');
      // @ts-expect-error
      ciph = Buffer.concat([ciph, cipher.final('buffer')]);

      const decipher = crypto.createDecipheriv('des-ede3-cbc', key, iv);
      let txt = decipher.update(ciph, 'buffer', 'utf8');
      txt += decipher.final('utf8');

      assert.strictEqual(
        txt,
        plaintext,
        `encryption/decryption with key ${key} and iv ${iv}`
      );
    });
  }

  // function testCipher3(key: string, iv: string) {
  //   it('test3 + ' + key + ' + ' + iv, () => {
  //     // Test encryption and decryption with explicit key and iv.
  //     // AES Key Wrap test vector comes from RFC3394
  //     const plaintext = Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex');

  //     const cipher = crypto.createCipheriv('id-aes128-wrap', key, iv);
  //     let ciph = cipher.update(plaintext, 'utf8', 'buffer');
  //     ciph = Buffer.concat([ciph, cipher.final('buffer')]);
  //     const ciph2 = Buffer.from(
  //       '1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5',
  //       'hex'
  //     );
  //     assert(ciph.equals(ciph2));
  //     const decipher = crypto.createDecipheriv('id-aes128-wrap', key, iv);
  //     let deciph = decipher.update(ciph, 'buffer');
  //     deciph = Buffer.concat([deciph, decipher.final()]);

  //     assert(
  //       deciph.equals(plaintext),
  //       `encryption/decryption with key ${key} and iv ${iv}`
  //     );
  //   });
  // }

  testCipher1('0123456789abcd0123456789', '12345678');
  testCipher1('0123456789abcd0123456789', Buffer.from('12345678'));
  testCipher1(Buffer.from('0123456789abcd0123456789'), '12345678');
  testCipher1(Buffer.from('0123456789abcd0123456789'), Buffer.from('12345678'));
  testCipher2(Buffer.from('0123456789abcd0123456789'), Buffer.from('12345678'));
});
