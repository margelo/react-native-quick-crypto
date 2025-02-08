import crypto from 'react-native-quick-crypto';
import { Buffer } from '@craftzdog/react-native-buffer';
import { describe, it } from '../../MochaRNAdapter';
import { expect } from 'chai';
import type {
  AesCbcParams,
  AesCtrParams,
  AesGcmParams,
  AnyAlgorithm,
  CryptoKey,
  CryptoKeyPair,
  DigestAlgorithm,
  EncryptDecryptParams,
  KeyUsage,
  RsaOaepParams,
} from '../../../../../react-native-quick-crypto/src/keys';
import rsa_oaep_fixtures from '../../fixtures/rsa';
import aes_cbc_fixtures from '../../fixtures/aes_cbc';
import aes_ctr_fixtures from '../../fixtures/aes_ctr';
import aes_gcm_fixtures from '../../fixtures/aes_gcm';
import { assertThrowsAsync } from '../util';
import { ab2str } from '../../../../../react-native-quick-crypto/src/Utils';

export type RsaEncryptDecryptTestVector = {
  name: string;
  publicKey: Buffer | null;
  publicKeyBuffer: ArrayBuffer;
  publicKeyFormat: string;
  privateKey: Buffer | null;
  privateKeyBuffer: ArrayBuffer | null;
  privateKeyFormat: string | null;
  algorithm: RsaOaepParams;
  hash: DigestAlgorithm;
  plaintext: ArrayBuffer;
  ciphertext: ArrayBuffer;
};

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

  // Test Encrypt/Decrypt RSA-OAEP
  {
    async function testRSAOAEP() {
      const buf = crypto.getRandomValues(new Uint8Array(50));
      const ec = new TextEncoder();
      const { publicKey, privateKey } = (await subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-384',
        },
        true,
        ['encrypt', 'decrypt'],
      )) as CryptoKeyPair;

      const ciphertext = await subtle.encrypt(
        {
          name: 'RSA-OAEP',
          label: ec.encode('a label'),
        },
        publicKey as CryptoKey,
        buf,
      );

      const plaintext = await subtle.decrypt(
        {
          name: 'RSA-OAEP',
          label: ec.encode('a label'),
        },
        privateKey as CryptoKey,
        ciphertext,
      );

      expect(Buffer.from(plaintext).toString('hex')).to.equal(
        Buffer.from(buf).toString('hex'),
      );
    }

    it('RSA-OAEP', async () => {
      await testRSAOAEP();
    });
  }

  // from https://github.com/nodejs/node/blob/main/test/parallel/test-webcrypto-encrypt-decrypt-rsa.js
  async function importRSAVectorKey(
    publicKeyBuffer: ArrayBuffer,
    _privateKeyBuffer: ArrayBuffer | null,
    name: AnyAlgorithm,
    hash: DigestAlgorithm,
    publicUsages: KeyUsage[],
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _privateUsages: KeyUsage[],
  ): Promise<CryptoKeyPair> {
    const publicKey = await subtle.importKey(
      'spki',
      publicKeyBuffer,
      { name, hash },
      false,
      publicUsages,
    );
    // const privateKey = await subtle.importKey(
    //   'pkcs8',
    //   privateKeyBuffer,
    //   { name, hash },
    //   false,
    //   privateUsages
    // ),

    return { publicKey, privateKey: undefined };
  }

  async function testRSADecryption({
    ciphertext,
    algorithm,
    plaintext,
    hash,
    publicKeyBuffer,
    privateKeyBuffer,
  }: RsaEncryptDecryptTestVector) {
    if (ciphertext === undefined) {
      return;
    }

    const { privateKey } = await importRSAVectorKey(
      publicKeyBuffer,
      privateKeyBuffer,
      algorithm.name,
      hash,
      ['encrypt'],
      ['decrypt'],
    );

    // TODO: remove condition when importKey() rsa pkcs8 is implemented
    if (privateKey !== undefined) {
      const encodedPlaintext = Buffer.from(plaintext).toString('hex');
      const result = await subtle.decrypt(
        algorithm,
        privateKey as CryptoKey,
        ciphertext,
      );

      expect(Buffer.from(result).toString('hex')).to.equal(encodedPlaintext);

      const ciphercopy = Buffer.from(ciphertext);

      // Modifying the ciphercopy after calling decrypt should just work
      const result2 = await subtle.decrypt(
        algorithm,
        privateKey as CryptoKey,
        ciphercopy,
      );
      ciphercopy[0] = 255 - ciphercopy[0];

      expect(Buffer.from(result2).toString('hex')).to.equal(encodedPlaintext);
    }
  }

  async function testRSAEncryption(
    {
      algorithm,
      plaintext,
      hash,
      publicKeyBuffer,
      privateKeyBuffer,
    }: RsaEncryptDecryptTestVector,
    modify = false,
  ) {
    const { publicKey, privateKey } = await importRSAVectorKey(
      publicKeyBuffer,
      privateKeyBuffer,
      algorithm.name,
      hash,
      ['encrypt'],
      ['decrypt'],
    );

    const plaintextCopy = Buffer.from(plaintext); // make a copy
    if (modify) {
      plaintext = plaintextCopy;
    }

    const result = await subtle.encrypt(
      algorithm,
      publicKey as CryptoKey,
      plaintext,
    );
    if (modify) {
      plaintext[0] = 255 - plaintext[0];
    }
    expect(result.byteLength).to.be.greaterThan(0);

    // TODO: remove condition when importKey() rsa pkcs8 is implemented
    if (privateKey !== undefined) {
      const encodedPlaintext = Buffer.from(plaintext).toString('hex');

      expect(result.byteLength * 8).to.equal(
        (privateKey as CryptoKey).algorithm.modulusLength,
      );

      const out = await subtle.decrypt(
        algorithm,
        privateKey as CryptoKey,
        result,
      );
      expect(Buffer.from(out).toString('hex')).to.equal(encodedPlaintext);
    }
  }

  async function testRSAEncryptionLongPlaintext({
    algorithm,
    plaintext,
    hash,
    publicKeyBuffer,
    privateKeyBuffer,
  }: RsaEncryptDecryptTestVector) {
    const { publicKey } = await importRSAVectorKey(
      publicKeyBuffer,
      privateKeyBuffer,
      algorithm.name,
      hash,
      ['encrypt'],
      ['decrypt'],
    );
    const newplaintext = new Uint8Array(plaintext.byteLength + 1);
    newplaintext.set(plaintext as Uint8Array, 0);
    newplaintext[plaintext.byteLength] = 32;

    return assertThrowsAsync(
      async () =>
        await subtle.encrypt(algorithm, publicKey as CryptoKey, newplaintext),
      'error in DoCipher, status: 2',
    );
  }

  async function testRSAEncryptionWrongKey({
    algorithm,
    plaintext,
    hash,
    publicKeyBuffer,
    privateKeyBuffer,
  }: RsaEncryptDecryptTestVector) {
    const { privateKey } = await importRSAVectorKey(
      publicKeyBuffer,
      privateKeyBuffer,
      algorithm.name,
      hash,
      ['encrypt'],
      ['decrypt'],
    );
    return assertThrowsAsync(
      async () =>
        await subtle.encrypt(algorithm, privateKey as CryptoKey, plaintext),
      "Cannot read property 'algorithm' of undefined",
    );
  }

  async function testRSAEncryptionBadUsage({
    algorithm,
    plaintext,
    hash,
    publicKeyBuffer,
    privateKeyBuffer,
  }: RsaEncryptDecryptTestVector) {
    const { publicKey } = await importRSAVectorKey(
      publicKeyBuffer,
      privateKeyBuffer,
      algorithm.name,
      hash,
      ['wrapKey'],
      ['decrypt'],
    );
    return assertThrowsAsync(
      async () =>
        await subtle.encrypt(algorithm, publicKey as CryptoKey, plaintext),
      'The requested operation is not valid',
    );
  }

  async function testRSADecryptionWrongKey({
    ciphertext,
    algorithm,
    hash,
    publicKeyBuffer,
    privateKeyBuffer,
  }: RsaEncryptDecryptTestVector) {
    if (ciphertext === undefined) {
      return;
    }

    const { publicKey } = await importRSAVectorKey(
      publicKeyBuffer,
      privateKeyBuffer,
      algorithm.name,
      hash,
      ['encrypt'],
      ['decrypt'],
    );

    return assertThrowsAsync(
      async () =>
        await subtle.decrypt(algorithm, publicKey as CryptoKey, ciphertext),
      'The requested operation is not valid',
    );
  }

  async function testRSADecryptionBadUsage({
    ciphertext,
    algorithm,
    hash,
    publicKeyBuffer,
    privateKeyBuffer,
  }: RsaEncryptDecryptTestVector) {
    if (ciphertext === undefined) {
      return;
    }

    const { publicKey } = await importRSAVectorKey(
      publicKeyBuffer,
      privateKeyBuffer,
      algorithm.name,
      hash,
      ['encrypt'],
      ['unwrapKey'],
    );

    return assertThrowsAsync(
      async () =>
        await subtle.decrypt(algorithm, publicKey as CryptoKey, ciphertext),
      'The requested operation is not valid',
    );
  }

  {
    const { passing } = rsa_oaep_fixtures;

    passing.forEach((vector: RsaEncryptDecryptTestVector) => {
      it(`RSA-OAEP decryption ${vector.name}`, async () => {
        await testRSADecryption(vector);
      });
      it(`RSA-OAEP decryption wrong key ${vector.name}`, async () => {
        await testRSADecryptionWrongKey(vector);
      });
      it(`RSA-OAEP decryption bad usage ${vector.name}`, async () => {
        await testRSADecryptionBadUsage(vector);
      });
      it(`RSA-OAEP encryption ${vector.name}`, async () => {
        await testRSAEncryption(vector);
      });
      it(`RSA-OAEP encryption ${vector.name}`, async () => {
        await testRSAEncryption(vector, true);
      });
      it(`RSA-OAEP encryption long plaintext ${vector.name}`, async () => {
        await testRSAEncryptionLongPlaintext(vector);
      });
      it(`RSA-OAEP encryption wrong key ${vector.name}`, async () => {
        await testRSAEncryptionWrongKey(vector);
      });
      it(`RSA-OAEP encryption bad usage ${vector.name}`, async () => {
        await testRSAEncryptionBadUsage(vector);
      });
    });
  }

  // from https://github.com/nodejs/node/blob/main/test/parallel/test-webcrypto-encrypt-decrypt.js
  // Test Encrypt/Decrypt AES-CTR
  {
    async function testAESCTR() {
      const buf = crypto.getRandomValues(new Uint8Array(50));
      const counter = crypto.getRandomValues(new Uint8Array(16));

      const key = await subtle.generateKey(
        {
          name: 'AES-CTR',
          length: 256,
        },
        true,
        ['encrypt', 'decrypt'],
      );

      const ciphertext = await subtle.encrypt(
        { name: 'AES-CTR', counter, length: 64 },
        key as CryptoKey,
        buf,
      );

      const plaintext = await subtle.decrypt(
        { name: 'AES-CTR', counter, length: 64 },
        key as CryptoKey,
        ciphertext,
      );

      expect(Buffer.from(plaintext).toString('hex')).to.equal(
        Buffer.from(buf).toString('hex'),
      );
    }

    it('AES-CTR', async () => {
      await testAESCTR();
    });
  }

  // Test Encrypt/Decrypt AES-CBC
  {
    async function testAESCBC() {
      const buf = crypto.getRandomValues(new Uint8Array(50));
      const iv = crypto.getRandomValues(new Uint8Array(16));

      const key = await subtle.generateKey(
        {
          name: 'AES-CBC',
          length: 256,
        },
        true,
        ['encrypt', 'decrypt'],
      );

      const ciphertext = await subtle.encrypt(
        { name: 'AES-CBC', iv },
        key as CryptoKey,
        buf,
      );

      const plaintext = await subtle.decrypt(
        { name: 'AES-CBC', iv },
        key as CryptoKey,
        ciphertext,
      );

      expect(Buffer.from(plaintext).toString('hex')).to.equal(
        Buffer.from(buf).toString('hex'),
      );
    }

    it('AES-CBC', async () => {
      await testAESCBC();
    });
  }

  // Test Encrypt/Decrypt AES-GCM
  {
    async function testAESGCM() {
      const buf = crypto.getRandomValues(new Uint8Array(50));
      const iv = crypto.getRandomValues(new Uint8Array(12));

      const key = await subtle.generateKey(
        {
          name: 'AES-GCM',
          length: 256,
        },
        true,
        ['encrypt', 'decrypt'],
      );

      const ciphertext = await subtle.encrypt(
        { name: 'AES-GCM', iv },
        key as CryptoKey,
        buf,
      );

      const plaintext = await subtle.decrypt(
        { name: 'AES-GCM', iv },
        key as CryptoKey,
        ciphertext,
      );

      expect(Buffer.from(plaintext).toString('hex')).to.equal(
        Buffer.from(buf).toString('hex'),
      );
    }

    it('AES-GCM', async () => {
      await testAESGCM();
    });
  }

  {
    async function testAESGCM2() {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const aad = crypto.getRandomValues(new Uint8Array(32));

      const secretKey = (await subtle.generateKey(
        {
          name: 'AES-GCM',
          length: 256,
        },
        false,
        ['encrypt', 'decrypt'],
      )) as CryptoKey;

      const encrypted = await subtle.encrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData: aad,
          tagLength: 128,
        },
        secretKey,
        crypto.getRandomValues(new Uint8Array(32)),
      );

      await subtle.decrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData: aad,
          tagLength: 128,
        },
        secretKey,
        new Uint8Array(encrypted),
      );
    }

    it('AES-GCM with iv & additionalData - default AuthTag length', async () => {
      await testAESGCM2();
    });
  }

  // from https://github.com/nodejs/node/blob/main/test/parallel/test-webcrypto-encrypt-decrypt-aes.js
  async function testAESEncrypt({
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
      ['encrypt', 'decrypt'],
    );
    const output = await subtle.encrypt(algorithm, key, plaintext);
    plaintextBuffer[0] = 255 - plaintextBuffer[0];

    expect(ab2str(output)).to.equal(ab2str(result), 'output != result');

    const checkAB = await subtle.decrypt(algorithm, key, output);
    // Converting the returned ArrayBuffer into a Buffer right away,
    // so that the next line works
    const check = Buffer.from(checkAB);
    check[0] = 255 - check[0];

    expect(ab2str(checkAB)).to.equal(
      ab2str(plaintextBuffer),
      'check != plaintext',
    );
  }

  async function testAESEncryptNoEncrypt({
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
      ['decrypt'],
    );

    await assertThrowsAsync(
      async () => await subtle.encrypt(algorithm, key, plaintext),
      'The requested operation is not valid for the provided key',
    );
  }

  async function testAESEncryptNoDecrypt({
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
      ['encrypt'],
    );

    const output = await subtle.encrypt(algorithm, key, plaintext);

    await assertThrowsAsync(
      async () => await subtle.decrypt(algorithm, key, output),
      'The requested operation is not valid for the provided key',
    );
  }

  async function testAESEncryptWrongAlg(
    { keyBuffer, algorithm, plaintext }: AesEncryptDecryptTestVector,
    alg: AnyAlgorithm,
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
      'The requested operation is not valid for the provided key',
    );
  }

  async function testAESDecrypt({
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
      ['encrypt', 'decrypt'],
    );

    await subtle.decrypt(algorithm, key, result);
  }

  // Test aes-cbc vectors
  {
    const { passing, failing, decryptionFailing } = aes_cbc_fixtures;

    passing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name } = algorithm as AesCbcParams;
      it(`testEncrypt passing ${name} ${keyLength}`, async () => {
        await testAESEncrypt(vector);
      });
      it(`testEncryptNoEncrypt passing ${name} ${keyLength}`, async () => {
        await testAESEncryptNoEncrypt(vector);
      });
      it(`testEncryptNoDecrypt passing ${name} ${keyLength}`, async () => {
        await testAESEncryptNoDecrypt(vector);
      });
      it(`testEncryptWrongAlg passing ${name} ${keyLength}`, async () => {
        await testAESEncryptWrongAlg(vector, 'AES-CTR');
      });
    });

    failing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name } = algorithm as AesCbcParams;
      it(`testEncrypt failing cbc ${name} ${keyLength}`, async () => {
        await assertThrowsAsync(
          async () => await testAESEncrypt(vector),
          'algorithm.iv must contain exactly 16 bytes',
        );
      });
      it(`testDecrypt failing cbc ${name} ${keyLength}`, async () => {
        await assertThrowsAsync(
          async () => await testAESDecrypt(vector),
          'algorithm.iv must contain exactly 16 bytes',
        );
      });
    });

    decryptionFailing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name } = algorithm as AesCbcParams;
      it(`testDecrypt decryptionFailing ${name} ${keyLength}`, async () => {
        await assertThrowsAsync(
          async () => await testAESDecrypt(vector),
          'error in DoCipher, status: 2',
        );
      });
    });
  }

  // Test aes-ctr vectors
  {
    const { passing, failing, decryptionFailing } = aes_ctr_fixtures;

    passing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name } = algorithm as AesCtrParams;
      it(`testEncrypt passing ${name} ${keyLength}`, async () => {
        await testAESEncrypt(vector);
      });
      it(`testEncryptNoEncrypt passing ${name} ${keyLength}`, async () => {
        await testAESEncryptNoEncrypt(vector);
      });
      it(`testEncryptNoDecrypt passing ${name} ${keyLength}`, async () => {
        await testAESEncryptNoDecrypt(vector);
      });
      it(`testEncryptWrongAlg passing ${name} ${keyLength}`, async () => {
        await testAESEncryptWrongAlg(vector, 'AES-CBC');
      });
    });

    // TODO(@jasnell): These fail for different reasons. Need to
    // make them consistent
    failing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name } = algorithm as AesCtrParams;
      it(`testEncrypt failing ctr ${name} ${keyLength}`, async () => {
        await assertThrowsAsync(
          async () => await testAESEncrypt(vector),
          'AES-CTR algorithm.length must be between 1 and 128',
        );
      });
      it(`testDecrypt failing ctr ${name} ${keyLength}`, async () => {
        await assertThrowsAsync(
          async () => await testAESDecrypt(vector),
          'AES-CTR algorithm.length must be between 1 and 128',
        );
      });
    });

    decryptionFailing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name } = algorithm as AesCtrParams;
      it(`testDecrypt decryptionFailing ${name} ${keyLength}`, async () => {
        await assertThrowsAsync(
          async () => await testAESDecrypt(vector),
          'error in DoCipher, status: 2',
        );
      });
    });
  }

  // Test aes-gcm vectors
  {
    const { passing, failing, decryptionFailing } = aes_gcm_fixtures;

    passing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name, tagLength } = algorithm as AesGcmParams;
      it(`testEncrypt passing ${name} ${keyLength} ${tagLength}`, async () => {
        await testAESEncrypt(vector);
      });
      it(`testEncryptNoEncrypt passing ${name} ${keyLength} ${tagLength}`, async () => {
        await testAESEncryptNoEncrypt(vector);
      });
      it(`testEncryptNoDecrypt passing ${name} ${keyLength} ${tagLength}`, async () => {
        await testAESEncryptNoDecrypt(vector);
      });
      it(`testEncryptWrongAlg passing ${name} ${keyLength} ${tagLength}`, async () => {
        await testAESEncryptWrongAlg(vector, 'AES-CBC');
      });
    });

    failing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name, tagLength } = algorithm as AesGcmParams;
      it(`testEncrypt failing gcm ${name} ${keyLength} ${tagLength}`, async () => {
        await assertThrowsAsync(
          async () => await testAESEncrypt(vector),
          'is not a valid AES-GCM tag length',
        );
      });
      it(`testDecrypt failing gcm ${name} ${keyLength} ${tagLength}`, async () => {
        await assertThrowsAsync(
          async () => await testAESDecrypt(vector),
          'is not a valid AES-GCM tag length',
        );
      });
    });

    decryptionFailing.forEach((vector: AesEncryptDecryptTestVector) => {
      const { algorithm, keyLength } = vector;
      const { name, tagLength } = algorithm as AesGcmParams;
      it(`testDecrypt decryptionFailing ${name} ${keyLength} ${tagLength}`, async () => {
        await assertThrowsAsync(
          async () => await testAESDecrypt(vector),
          'error in DoCipher, status: 2',
        );
      });
    });
  }
});
