// copied from https://github.com/nodejs/node/blob/master/test/parallel/test-crypto-hash.js
import { Buffer } from '@craftzdog/react-native-buffer';
import { assert } from 'chai';
import crypto from 'react-native-quick-crypto';
import { describe, it } from '../../MochaRNAdapter';

describe('createCipher/createDecipher', () => {
  function testCipher1(key: Buffer | string) {
    it('testCipher1 + ' + key, () => {
      // Test encryption and decryption
      const plaintext =
        'Keep this a secret? No! Tell everyone about quick-crypto!';
      const cipher = crypto.createCipher('aes192', key);

      // Encrypt plaintext which is in utf8 format
      // to a ciphertext which will be in hex
      let ciph = cipher.update(plaintext, 'utf-8', 'hex') as string;
      // Only use binary or hex, not base64.
      ciph += cipher.final('hex');

      const decipher = crypto.createDecipher('aes192', key);
      let txt = decipher.update(ciph, 'hex', 'utf-8');
      txt += decipher.final('utf-8') as string;

      assert.strictEqual(txt, plaintext);

      // Streaming cipher interface
      // NB: In real life, it's not guaranteed that you can get all of it
      // in a single read() like this.  But in this case, we know it's
      // quite small, so there's no harm.
      const cStream = crypto.createCipher('aes192', key);
      cStream.end(plaintext);
      ciph = cStream.read();

      const dStream = crypto.createDecipher('aes192', key);
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
      const cipher = crypto.createCipher('aes256', key);

      // Encrypt plaintext which is in utf8 format to a ciphertext which will be in
      // Base64.
      let ciph = cipher.update(plaintext, 'utf8', 'base64') as string;
      ciph += cipher.final('base64');

      const decipher = crypto.createDecipher('aes256', key);
      let txt = decipher.update(ciph, 'base64', 'utf8');
      txt += decipher.final('utf8') as string;

      assert.strictEqual(txt, plaintext);
    });
  }

  testCipher1('MySecretKey123');
  testCipher1(Buffer.from('MySecretKey123'));

  testCipher2('0123456789abcdef');
  testCipher2(Buffer.from('0123456789abcdef'));

  it('#createCipher with invalid algorithm should throw', () => {
    try {
      // @ts-expect-error invalid algorithm
      crypto.createCipher('blah', 'secret');
      assert.fail('createCipher with invalid algo did not throw');
    } catch {
      // Intentionally left blank
    }
  });

  it('Base64 padding regression test', () => {
    // @ts-expect-error invalid algorithm
    const c = crypto.createCipher('aes-256-cbc', 'secret');
    const s = c.update('test', 'utf8', 'base64') + c.final('base64');
    assert.strictEqual(s, '375oxUQCIocvxmC5At+rvA==');
  });

  it('Calling Cipher.final() or Decipher.final() twice should error', () => {
    // @ts-expect-error invalid algorithm
    const c = crypto.createCipher('aes-256-cbc', 'secret');
    try {
      // @ts-expect-error bad encoding
      c.final('xxx');
    } catch {
      /* Ignore. */
    }
    try {
      // @ts-expect-error bad encoding
      c.final('xxx');
    } catch {
      /* Ignore. */
    }
    try {
      // @ts-expect-error bad encoding
      c.final('xxx');
    } catch {
      /* Ignore. */
    }
    // @ts-expect-error invalid algorithm
    const d = crypto.createDecipher('aes-256-cbc', 'secret');
    try {
      // @ts-expect-error bad encoding
      d.final('xxx');
    } catch {
      /* Ignore. */
    }
    try {
      // @ts-expect-error bad encoding
      d.final('xxx');
    } catch {
      /* Ignore. */
    }
    try {
      // @ts-expect-error bad encoding
      d.final('xxx');
    } catch {
      /* Ignore. */
    }
  });

  it('string to Cipher#update() should not assert.', () => {
    const c = crypto.createCipher('aes192', '0123456789abcdef');
    c.update('update');
    c.final();
  });

  it("'utf-8' and 'utf8' are identical.", () => {
    let c = crypto.createCipher('aes192', '0123456789abcdef');
    // @ts-expect-error bad encoding
    c.update('update', ''); // Defaults to "utf8".
    c.final('utf-8'); // Should not throw.

    c = crypto.createCipher('aes192', '0123456789abcdef');
    c.update('update', 'utf8');
    c.final('utf-8'); // Should not throw.

    c = crypto.createCipher('aes192', '0123456789abcdef');
    c.update('update', 'utf-8');
    c.final('utf8'); // Should not throw.
  });

  it('Regression tests for https://github.com/nodejs/node/issues/8236', () => {
    const key = '0123456789abcdef';
    const plaintext = 'Top secret!!!';
    const c = crypto.createCipher('aes192', key);
    let ciph = c.update(plaintext, 'utf16le', 'base64') as string;
    ciph += c.final('base64');

    let decipher = crypto.createDecipher('aes192', key);

    let txt;
    txt = decipher.update(ciph, 'base64', 'ucs2');
    txt += decipher.final('ucs2') as string;
    assert.strictEqual(txt, plaintext);

    decipher = crypto.createDecipher('aes192', key);
    txt = decipher.update(ciph, 'base64', 'ucs-2');
    txt += decipher.final('ucs-2') as string;
    assert.strictEqual(txt, plaintext);

    decipher = crypto.createDecipher('aes192', key);
    txt = decipher.update(ciph, 'base64', 'utf16le') as string;
    txt += decipher.final('utf16le');
    assert.strictEqual(txt, plaintext);
  });

  it('setAutoPadding/setAuthTag/setAAD should return `this`', () => {
    const key = '0123456789';
    const tagbuf = Buffer.from('auth_tag');
    const aadbuf = Buffer.from('aadbuf');
    const decipher = crypto.createDecipher('aes-256-gcm', key);
    assert.strictEqual(decipher.setAutoPadding(), decipher, 'setAutoPadding');
    // TODO: this is erroring out in MGLCipherHostObject.cpp.  Search for "Invalid authentication tag length"
    assert.strictEqual(decipher.setAuthTag(tagbuf), decipher, 'setAuthTag');
    assert.strictEqual(decipher.setAAD(aadbuf), decipher, 'setAAD');
  });
});
