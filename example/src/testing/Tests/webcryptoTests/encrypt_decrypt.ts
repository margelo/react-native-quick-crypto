import crypto from 'react-native-quick-crypto';
import { describe, it } from '../../MochaRNAdapter';
import { expect } from 'chai';
import type {
  AesCbcParams,
  AesCtrParams,
  AesGcmParams,
  AnyAlgorithm,
  CryptoKey,
  EncryptDecryptParams,
} from '../../../../../src/keys';
import aes_cbc_fixtures from '../../fixtures/aes_cbc';
import aes_ctr_fixtures from '../../fixtures/aes_ctr';
import aes_gcm_fixtures from '../../fixtures/aes_gcm';
import { assertThrowsAsync } from '../util';
import { ab2str } from '../../../../../src/Utils';

export type AesEncryptDecryptTestVector = {
  keyBuffer?: ArrayBuffer;
  algorithm?: EncryptDecryptParams;
  plaintext?: ArrayBuffer;
  result?: ArrayBuffer;
  keyLength?: string;
};

export type VectorValue = Record<string, ArrayBuffer>;
export type BadPadding = {
  zeroPadChar: ArrayBuffer;
  bigPadChar: ArrayBuffer;
  inconsistentPadChars: ArrayBuffer;
};
export type BadPaddingVectorValue = Record<string, BadPadding>;

const { subtle } = crypto;

// This is only a partial test. The WebCrypto Web Platform Tests
// will provide much greater coverage.

describe('subtle - encrypt / decrypt', () => {
  // from https://github.com/nodejs/node/blob/main/test/parallel/test-webcrypto-encrypt-decrypt.js

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

  // TODO: when RSA is fully-implemented, add the tests in
  //  * test-webcrypto-encrypt-decrypt-rsa.js

  // from https://github.com/nodejs/node/blob/main/test/parallel/test-webcrypto-encrypt-decrypt.js
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

  // from https://github.com/nodejs/node/blob/main/test/parallel/test-webcrypto-encrypt-decrypt-aes.js
  async function testEncrypt({
    keyBuffer,
    algorithm,
    plaintext,
    result,
  }: AesEncryptDecryptTestVector): Promise<void> {
    // keeps typescript happy
    if (!keyBuffer || !algorithm || !plaintext || !result) {
      throw new Error('Missing test vector');
    }

    // Using a copy of plaintext to prevent tampering of the original
    const plaintextBuffer = Buffer.from(plaintext);

    const key = await subtle.importKey(
      'raw',
      keyBuffer,
      { name: algorithm.name },
      false,
      ['encrypt', 'decrypt']
    );
    const output = await subtle.encrypt(algorithm, key, plaintext);
    // @ts-expect-error
    plaintextBuffer[0] = 255 - plaintextBuffer[0];

    expect(ab2str(output)).to.equal(ab2str(result), 'output != result');

    const checkAB = await subtle.decrypt(algorithm, key, output);
    // Converting the returned ArrayBuffer into a Buffer right away,
    // so that the next line works
    const check = Buffer.from(checkAB);
    // @ts-expect-error
    check[0] = 255 - check[0];

    expect(ab2str(checkAB)).to.equal(
      ab2str(plaintextBuffer),
      'check != plaintext'
    );
  }

  async function testEncryptNoEncrypt({
    keyBuffer,
    algorithm,
    plaintext,
  }: AesEncryptDecryptTestVector): Promise<void> {
    // keeps typescript happy
    if (!keyBuffer || !algorithm || !plaintext) {
      throw new Error('Missing test vector');
    }

    const key = await subtle.importKey(
      'raw',
      keyBuffer,
      { name: algorithm.name },
      false,
      ['decrypt']
    );

    await assertThrowsAsync(
      async () => await subtle.encrypt(algorithm, key, plaintext),
      'The requested operation is not valid for the provided key'
    );
  }

  async function testEncryptNoDecrypt({
    keyBuffer,
    algorithm,
    plaintext,
  }: AesEncryptDecryptTestVector): Promise<void> {
    // keeps typescript happy
    if (!keyBuffer || !algorithm || !plaintext) {
      throw new Error('Missing test vector');
    }

    const key = await subtle.importKey(
      'raw',
      keyBuffer,
      { name: algorithm.name },
      false,
      ['encrypt']
    );

    const output = await subtle.encrypt(algorithm, key, plaintext);

    await assertThrowsAsync(
      async () => await subtle.decrypt(algorithm, key, output),
      'The requested operation is not valid for the provided key'
    );
  }

  async function testEncryptWrongAlg(
    { keyBuffer, algorithm, plaintext }: AesEncryptDecryptTestVector,
    alg: AnyAlgorithm
  ): Promise<void> {
    // keeps typescript happy
    if (!keyBuffer || !algorithm || !plaintext) {
      throw new Error('Missing test vector');
    }

    expect(algorithm.name).to.not.equal(alg);
    const key = await subtle.importKey('raw', keyBuffer, { name: alg }, false, [
      'encrypt',
    ]);

    await assertThrowsAsync(
      async () => await subtle.encrypt(algorithm, key, plaintext),
      'The requested operation is not valid for the provided key'
    );
  }

  async function testDecrypt({
    keyBuffer,
    algorithm,
    result,
  }: AesEncryptDecryptTestVector): Promise<void> {
    // keeps typescript happy
    if (!keyBuffer || !algorithm || !result) {
      throw new Error('Missing test vector');
    }

    const key = await subtle.importKey(
      'raw',
      keyBuffer,
      { name: algorithm.name },
      false,
      ['encrypt', 'decrypt']
    );

    await subtle.decrypt(algorithm, key, result);
  }

  // Test aes-cbc vectors
  {
    let { passing, failing, decryptionFailing } = aes_cbc_fixtures;

    passing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name } = algorithm as AesCbcParams;
      it(`testEncrypt passing ${name} ${keyLength}`, async () => {
        await testEncrypt(vector);
      });
      it(`testEncryptNoEncrypt passing ${name} ${keyLength}`, async () => {
        await testEncryptNoEncrypt(vector);
      });
      it(`testEncryptNoDecrypt passing ${name} ${keyLength}`, async () => {
        await testEncryptNoDecrypt(vector);
      });
      it(`testEncryptWrongAlg passing ${name} ${keyLength}`, async () => {
        await testEncryptWrongAlg(vector, 'AES-CTR');
      });
    });

    failing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name } = algorithm as AesCbcParams;
      it(`testEncrypt failing ${name} ${keyLength}`, async () => {
        await assertThrowsAsync(
          async () => await testEncrypt(vector),
          'algorithm.iv must contain exactly 16 bytes'
        );
      });
      it(`testDecrypt failing ${name} ${keyLength}`, async () => {
        await assertThrowsAsync(
          async () => await testDecrypt(vector),
          'algorithm.iv must contain exactly 16 bytes'
        );
      });
    });

    decryptionFailing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name } = algorithm as AesCbcParams;
      it(`testDecrypt decryptionFailing ${name} ${keyLength}`, async () => {
        await assertThrowsAsync(
          async () => await testDecrypt(vector),
          'error in DoCipher, status: 2'
        );
      });
    });
  }

  // Test aes-ctr vectors
  {
    let { passing, failing, decryptionFailing } = aes_ctr_fixtures;

    passing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name } = algorithm as AesCtrParams;
      it(`testEncrypt passing ${name} ${keyLength}`, async () => {
        await testEncrypt(vector);
      });
      it(`testEncryptNoEncrypt passing ${name} ${keyLength}`, async () => {
        await testEncryptNoEncrypt(vector);
      });
      it(`testEncryptNoDecrypt passing ${name} ${keyLength}`, async () => {
        await testEncryptNoDecrypt(vector);
      });
      it(`testEncryptWrongAlg passing ${name} ${keyLength}`, async () => {
        await testEncryptWrongAlg(vector, 'AES-CBC');
      });
    });

    // TODO(@jasnell): These fail for different reasons. Need to
    // make them consistent
    failing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name } = algorithm as AesCtrParams;
      it(`testEncrypt failing ${name} ${keyLength}`, async () => {
        await assertThrowsAsync(
          async () => await testEncrypt(vector),
          'AES-CTR algorithm.length must be between 1 and 128'
        );
      });
      it(`testDecrypt failing ${name} ${keyLength}`, async () => {
        await assertThrowsAsync(
          async () => await testDecrypt(vector),
          'AES-CTR algorithm.length must be between 1 and 128'
        );
      });
    });

    decryptionFailing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name } = algorithm as AesCtrParams;
      it(`testDecrypt decryptionFailing ${name} ${keyLength}`, async () => {
        await assertThrowsAsync(
          async () => await testDecrypt(vector),
          'error in DoCipher, status: 2'
        );
      });
    });
  }

  // Test aes-gcm vectors
  {
    let { passing, failing, decryptionFailing } = aes_gcm_fixtures;

    passing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name } = algorithm as AesGcmParams;
      it(`testEncrypt passing ${name} ${keyLength}`, async () => {
        await testEncrypt(vector);
      });
      it(`testEncryptNoEncrypt passing ${name} ${keyLength}`, async () => {
        await testEncryptNoEncrypt(vector);
      });
      it(`testEncryptNoDecrypt passing ${name} ${keyLength}`, async () => {
        await testEncryptNoDecrypt(vector);
      });
      it(`testEncryptWrongAlg passing ${name} ${keyLength}`, async () => {
        await testEncryptWrongAlg(vector, 'AES-CBC');
      });
    });

    failing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name } = algorithm as AesGcmParams;
      it(`testEncrypt failing ${name} ${keyLength}`, async () => {
        await assertThrowsAsync(
          async () => await testEncrypt(vector),
          'is not a valid AES-GCM tag length'
        );
      });
      it(`testDecrypt failing ${name} ${keyLength}`, async () => {
        await assertThrowsAsync(
          async () => await testDecrypt(vector),
          'is not a valid AES-GCM tag length'
        );
      });
    });

    decryptionFailing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name } = algorithm as AesGcmParams;
      it(`testDecrypt decryptionFailing ${name} ${keyLength}`, async () => {
        await assertThrowsAsync(
          async () => await testDecrypt(vector),
          'error in DoCipher, status: 2'
        );
      });
    });
  }

  {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = crypto.getRandomValues(new Uint8Array(32));

    async function testAESGCM2() {
      const secretKey = (await subtle.generateKey(
        {
          name: 'AES-GCM',
          length: 256,
        },
        false,
        ['encrypt', 'decrypt']
      )) as CryptoKey;

      const encrypted = await subtle.encrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData: aad,
          tagLength: 128,
        },
        secretKey,
        crypto.getRandomValues(new Uint8Array(32))
      );

      await subtle.decrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData: aad,
          tagLength: 128,
        },
        secretKey,
        new Uint8Array(encrypted)
      );
    }

    it('AES-GCM with iv & additionalData - default AuthTag length', async () => {
      await testAESGCM2();
    });
  }
});
