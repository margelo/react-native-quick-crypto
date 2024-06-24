import crypto from 'react-native-quick-crypto';
import { describe, it } from '../../MochaRNAdapter';
import { expect } from 'chai';

// polyfill encoders
// @ts-expect-error
import { polyfillGlobal } from 'react-native/Libraries/Utilities/PolyfillFunctions';
import RNFE from 'react-native-fast-encoder';
import type { CryptoKey } from '../../../../../src/keys';
polyfillGlobal('TextEncoder', () => RNFE);

const { subtle } = crypto;

// This is only a partial test. The WebCrypto Web Platform Tests
// will provide much greater coverage.

describe('subtle - encrypt / decrypt', () => {
  // // Test Encrypt/Decrypt RSA-OAEP
  // {
  //   const buf = crypto.getRandomValues(new Uint8Array(50));

  //   async function test() {
  //     const ec = new TextEncoder();
  //     const { publicKey, privateKey } = await subtle.generateKey({
  //       name: 'RSA-OAEP',
  //       modulusLength: 2048,
  //       publicExponent: new Uint8Array([1, 0, 1]),
  //       hash: 'SHA-384',
  //     }, true, ['encrypt', 'decrypt']);

  //     const ciphertext = await subtle.encrypt({
  //       name: 'RSA-OAEP',
  //       label: ec.encode('a label')
  //     }, publicKey, buf);

  //     const plaintext = await subtle.decrypt({
  //       name: 'RSA-OAEP',
  //       label: ec.encode('a label')
  //     }, privateKey, ciphertext);

  //     assert.strictEqual(
  //       Buffer.from(plaintext).toString('hex'),
  //       Buffer.from(buf).toString('hex'));
  //   }

  //   test().then(common.mustCall());
  // }

  // Test Encrypt/Decrypt AES-CTR
  {
    const buf = crypto.getRandomValues(new Uint8Array(50));
    const counter = crypto.getRandomValues(new Uint8Array(16));

    async function testAESCTR() {
      const key = await subtle.generateKey(
        {
          name: 'AES-CTR',
          length: 256,
        },
        true,
        ['encrypt', 'decrypt']
      );

      const ciphertext = await subtle.encrypt(
        { name: 'AES-CTR', counter, length: 64 },
        key as CryptoKey,
        buf
      );

      const plaintext = await subtle.decrypt(
        { name: 'AES-CTR', counter, length: 64 },
        key as CryptoKey,
        ciphertext
      );

      expect(Buffer.from(plaintext).toString('hex')).to.equal(
        Buffer.from(buf).toString('hex')
      );
    }

    it('AES-CTR', async () => {
      await testAESCTR();
    });
  }

  // Test Encrypt/Decrypt AES-CBC
  {
    const buf = crypto.getRandomValues(new Uint8Array(50));
    const iv = crypto.getRandomValues(new Uint8Array(16));

    async function testAESCBC() {
      const key = await subtle.generateKey(
        {
          name: 'AES-CBC',
          length: 256,
        },
        true,
        ['encrypt', 'decrypt']
      );

      const ciphertext = await subtle.encrypt(
        { name: 'AES-CBC', iv },
        key as CryptoKey,
        buf
      );

      const plaintext = await subtle.decrypt(
        { name: 'AES-CBC', iv },
        key as CryptoKey,
        ciphertext
      );

      expect(Buffer.from(plaintext).toString('hex')).to.equal(
        Buffer.from(buf).toString('hex')
      );
    }

    it('AES-CBC', async () => {
      await testAESCBC();
    });
  }

  // Test Encrypt/Decrypt AES-GCM
  {
    const buf = crypto.getRandomValues(new Uint8Array(50));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    async function testAESGCM() {
      const key = await subtle.generateKey(
        {
          name: 'AES-GCM',
          length: 256,
        },
        true,
        ['encrypt', 'decrypt']
      );

      const ciphertext = await subtle.encrypt(
        { name: 'AES-GCM', iv },
        key as CryptoKey,
        buf
      );

      const plaintext = await subtle.decrypt(
        { name: 'AES-GCM', iv },
        key as CryptoKey,
        ciphertext
      );

      expect(Buffer.from(plaintext).toString('hex')).to.equal(
        Buffer.from(buf).toString('hex')
      );
    }

    it('AES-GCM', async () => {
      await testAESGCM();
    });
  }

  // TODO: when algorithms are fully-implemented, add the tests in
  //  * test-webcrypto-encrypt-decrypt-aes.js
  //  * test-webcrypto-encrypt-decrypt-rsa.js
});
