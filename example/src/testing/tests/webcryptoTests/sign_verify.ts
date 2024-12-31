import type { CryptoKey, CryptoKeyPair } from '../../../../../src/keys';
import crypto from 'react-native-quick-crypto';
import { describe, it } from '../../MochaRNAdapter';
import { expect } from 'chai';

const { subtle } = crypto;
const encoder = new TextEncoder();

describe('subtle - sign / verify', () => {
  // // Test Sign/Verify RSASSA-PKCS1-v1_5
  // {
  //   async function test(data) {
  //     const ec = new TextEncoder();
  //     const { publicKey, privateKey } = await subtle.generateKey({
  //       name: 'RSASSA-PKCS1-v1_5',
  //       modulusLength: 1024,
  //       publicExponent: new Uint8Array([1, 0, 1]),
  //       hash: 'SHA-256'
  //     }, true, ['sign', 'verify']);

  //     const signature = await subtle.sign({
  //       name: 'RSASSA-PKCS1-v1_5'
  //     }, privateKey, ec.encode(data));

  //     assert(await subtle.verify({
  //       name: 'RSASSA-PKCS1-v1_5'
  //     }, publicKey, signature, ec.encode(data)));
  //   }

  //   test('hello world').then(common.mustCall());
  // }

  // // Test Sign/Verify RSA-PSS
  // {
  //   async function test(data) {
  //     const ec = new TextEncoder();
  //     const { publicKey, privateKey } = await subtle.generateKey({
  //       name: 'RSA-PSS',
  //       modulusLength: 4096,
  //       publicExponent: new Uint8Array([1, 0, 1]),
  //       hash: 'SHA-256'
  //     }, true, ['sign', 'verify']);

  //     const signature = await subtle.sign({
  //       name: 'RSA-PSS',
  //       saltLength: 256,
  //     }, privateKey, ec.encode(data));

  //     assert(await subtle.verify({
  //       name: 'RSA-PSS',
  //       saltLength: 256,
  //     }, publicKey, signature, ec.encode(data)));
  //   }

  //   test('hello world').then(common.mustCall());
  // }

  // Test Sign/Verify ECDSA
  {
    async function test(data: string) {
      const pair = await subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-384' },
        true,
        ['sign', 'verify'],
      );
      const { publicKey, privateKey } = pair as CryptoKeyPair;

      const signature = await subtle.sign(
        { name: 'ECDSA', hash: 'SHA-384' },
        privateKey as CryptoKey,
        encoder.encode(data),
      );

      expect(
        await subtle.verify(
          { name: 'ECDSA', hash: 'SHA-384' },
          publicKey as CryptoKey,
          signature,
          encoder.encode(data),
        ),
      ).to.equal(true);
    }

    it('ECDSA', async () => {
      await test('hello world');
    });
  }

  it('ECDSA with HashAlgorithmIdentifier', async () => {
    const pair = await subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    const { publicKey, privateKey } = pair as CryptoKeyPair;
    const signature = await subtle.sign(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      privateKey as CryptoKey,
      encoder.encode('hello world'),
    );
    expect(
      await subtle.verify(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        publicKey as CryptoKey,
        signature,
        encoder.encode('hello world'),
      ),
    ).to.equal(true);
  });

  // // Test Sign/Verify HMAC
  // {
  //   async function test(data) {
  //     const ec = new TextEncoder();

  //     const key = await subtle.generateKey({
  //       name: 'HMAC',
  //       length: 256,
  //       hash: 'SHA-256'
  //     }, true, ['sign', 'verify']);

  //     const signature = await subtle.sign({
  //       name: 'HMAC',
  //     }, key, ec.encode(data));

  //     assert(await subtle.verify({
  //       name: 'HMAC',
  //     }, key, signature, ec.encode(data)));
  //   }

  //   test('hello world').then(common.mustCall());
  // }

  // // Test Sign/Verify Ed25519
  // {
  //   async function test(data) {
  //     const ec = new TextEncoder();
  //     const { publicKey, privateKey } = await subtle.generateKey({
  //       name: 'Ed25519',
  //     }, true, ['sign', 'verify']);

  //     const signature = await subtle.sign({
  //       name: 'Ed25519',
  //     }, privateKey, ec.encode(data));

  //     assert(await subtle.verify({
  //       name: 'Ed25519',
  //     }, publicKey, signature, ec.encode(data)));
  //   }

  //   test('hello world').then(common.mustCall());
  // }

  // // Test Sign/Verify Ed448
  // {
  //   async function test(data) {
  //     const ec = new TextEncoder();
  //     const { publicKey, privateKey } = await subtle.generateKey({
  //       name: 'Ed448',
  //     }, true, ['sign', 'verify']);

  //     const signature = await subtle.sign({
  //       name: 'Ed448',
  //     }, privateKey, ec.encode(data));

  //     assert(await subtle.verify({
  //       name: 'Ed448',
  //     }, publicKey, signature, ec.encode(data)));
  //   }

  //   test('hello world').then(common.mustCall());
  // }

  // TODO: when other algorithms are implemented, add the tests in
  //  * test-webcrypto-sign-verify-ecdsa.js
  //  * test-webcrypto-sign-verify-eddsa.js
  //  * test-webcrypto-sign-verify-hmac.js
  //  * test-webcrypto-sign-verify-rsa.js
});
