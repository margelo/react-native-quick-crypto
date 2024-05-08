// copied from https://github.com/nodejs/node/blob/master/test/parallel/test-crypto-hash.js
import { Buffer } from '@craftzdog/react-native-buffer';
import { assert } from 'chai';
import QuickCrypto from 'react-native-quick-crypto';
import { describe, it } from '../../MochaRNAdapter';

describe('createCipher/createDecipher', () => {
  'use strict';
  function testCipher1(key: Buffer | string) {
    it('testCipher1 + ' + key, () => {
      // Test encryption and decryption
      const plaintext =
        'Keep this a secret? No! Tell everyone about quick-crypto!';
      const cipher = QuickCrypto.createCipher('aes192', key);

      // Encrypt plaintext which is in utf8 format
      // to a ciphertext which will be in hex
      let ciph = cipher.update(plaintext, 'utf-8', 'hex');
      // Only use binary or hex, not base64.
      ciph += cipher.final('hex');

      const decipher = QuickCrypto.createDecipher('aes192', key);
      let txt = decipher.update(ciph, 'hex', 'utf-8');
      txt += decipher.final('utf-8');

      assert.strictEqual(txt, plaintext);

      // Streaming cipher interface
      // NB: In real life, it's not guaranteed that you can get all of it
      // in a single read() like this.  But in this case, we know it's
      // quite small, so there's no harm.
      const cStream = QuickCrypto.createCipher('aes192', key);
      cStream.end(plaintext);
      ciph = cStream.read();

      const dStream = QuickCrypto.createDecipher('aes192', key);
      dStream.end(ciph);
      txt = dStream.read().toString('utf8');
      assert.strictEqual(txt, plaintext);
    });
  }

  function testCipher2(key: string | Buffer) {
    it('testCipher2 + ' + key, () => {
      // Encryption and decryption with Base64.
      // Reported in https://github.com/joyent/node/issues/738
      const plaintext =
        '32|RmVZZkFUVmpRRkp0TmJaUm56ZU9qcnJkaXNNWVNpTTU*|iXmckfRWZBGWWELw' +
        'eCBsThSsfUHLeRe0KCsK8ooHgxie0zOINpXxfZi/oNG7uq9JWFVCk70gfzQH8ZUJ' +
        'jAfaFg**';
      const cipher = QuickCrypto.createCipher('aes256', key);

      // Encrypt plaintext which is in utf8 format to a ciphertext which will be in
      // Base64.
      let ciph = cipher.update(plaintext, 'utf8', 'base64');
      ciph += cipher.final('base64');

      const decipher = QuickCrypto.createDecipher('aes256', key);
      let txt = decipher.update(ciph, 'base64', 'utf8');
      txt += decipher.final('utf8');

      assert.strictEqual(txt, plaintext);
    });
  }

  testCipher1('MySecretKey123');
  testCipher1(Buffer.from('MySecretKey123'));

  testCipher2('0123456789abcdef');
  testCipher2(Buffer.from('0123456789abcdef'));

  it('#createCipher with invalid algorithm should throw', () => {
    try {
      QuickCrypto.createCipher('blah', 'secret');
      assert.fail('createCipher with invalid algo did not throw');
    } catch {
      // Intentionally left blank
    }
  });

  it('Base64 padding regression test', () => {
    const c = QuickCrypto.createCipher('aes-256-cbc', 'secret');
    const s = c.update('test', 'utf8', 'base64') + c.final('base64');
    assert.strictEqual(s, '375oxUQCIocvxmC5At+rvA==');
  });

  it('Calling Cipher.final() or Decipher.final() twice should error', () => {
    const c = QuickCrypto.createCipher('aes-256-cbc', 'secret');
    try {
      // @ts-expect-error
      c.final('xxx');
    } catch {
      /* Ignore. */
    }
    try {
      // @ts-expect-error
      c.final('xxx');
    } catch {
      /* Ignore. */
    }
    try {
      // @ts-expect-error
      c.final('xxx');
    } catch {
      /* Ignore. */
    }
    const d = QuickCrypto.createDecipher('aes-256-cbc', 'secret');
    try {
      // @ts-expect-error
      d.final('xxx');
    } catch {
      /* Ignore. */
    }
    try {
      // @ts-expect-error
      d.final('xxx');
    } catch {
      /* Ignore. */
    }
    try {
      // @ts-expect-error
      d.final('xxx');
    } catch {
      /* Ignore. */
    }
  });

  it('string to Cipher#update() should not assert.', () => {
    const c = QuickCrypto.createCipher('aes192', '0123456789abcdef');
    c.update('update');
    c.final();
  });

  it("'utf-8' and 'utf8' are identical.", () => {
    let c = QuickCrypto.createCipher('aes192', '0123456789abcdef');
    // @ts-expect-error
    c.update('update', ''); // Defaults to "utf8".
    c.final('utf-8'); // Should not throw.

    c = QuickCrypto.createCipher('aes192', '0123456789abcdef');
    c.update('update', 'utf8');
    c.final('utf-8'); // Should not throw.

    c = QuickCrypto.createCipher('aes192', '0123456789abcdef');
    c.update('update', 'utf-8');
    c.final('utf8'); // Should not throw.
  });

  it('Regression tests for https://github.com/nodejs/node/issues/8236', () => {
    const key = '0123456789abcdef';
    const plaintext = 'Top secret!!!';
    const c = QuickCrypto.createCipher('aes192', key);
    let ciph = c.update(plaintext, 'utf16le', 'base64');
    ciph += c.final('base64');

    let decipher = QuickCrypto.createDecipher('aes192', key);

    let txt;
    txt = decipher.update(ciph, 'base64', 'ucs2');
    txt += decipher.final('ucs2');
    assert.strictEqual(txt, plaintext);

    decipher = QuickCrypto.createDecipher('aes192', key);
    txt = decipher.update(ciph, 'base64', 'ucs-2');
    txt += decipher.final('ucs-2');
    assert.strictEqual(txt, plaintext);

    decipher = QuickCrypto.createDecipher('aes192', key);
    // @ts-expect-error
    txt = decipher.update(ciph, 'base64', 'utf-16le');
    // @ts-expect-error
    txt += decipher.final('utf-16le');
    assert.strictEqual(txt, plaintext);
  });

  it('setAutoPadding/setAuthTag/setAAD should return `this`', () => {
    const key = '0123456789';
    const tagbuf = Buffer.from('auth_tag');
    const aadbuf = Buffer.from('aadbuf');
    const decipher = QuickCrypto.createDecipher('aes-256-gcm', key);

    assert.strictEqual(decipher.setAutoPadding(), decipher);
    assert.strictEqual(decipher.setAuthTag(tagbuf), decipher);
    assert.strictEqual(decipher.setAAD(aadbuf), decipher);
  });
});
