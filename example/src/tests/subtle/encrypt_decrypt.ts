import {
  bufferLikeToArrayBuffer,
  getRandomValues,
  subtle,
} from 'react-native-quick-crypto';
import { Buffer } from '@craftzdog/react-native-buffer';
import { test } from '../util';
import { expect } from 'chai';
import type {
  AesCbcParams,
  AesCtrParams,
  AesGcmParams,
  AnyAlgorithm,
  CryptoKey,
  DigestAlgorithm,
  EncryptDecryptParams,
  KeyUsage,
  RsaOaepParams,
} from 'react-native-quick-crypto';

// Local interface to match what subtle.generateKey actually returns
interface TestCryptoKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}
import rsa_oaep_fixtures from '../../fixtures/rsa';
import aes_cbc_fixtures from '../../fixtures/aes_cbc';
import aes_ctr_fixtures from '../../fixtures/aes_ctr';
import aes_gcm_fixtures from '../../fixtures/aes_gcm';
import { assertThrowsAsync } from '../util';
import { ab2str } from 'react-native-quick-crypto';

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

// This is only a partial test. The WebCrypto Web Platform Tests
// will provide much greater coverage.

const SUITE = 'subtle.encrypt/decrypt';

// from https://github.com/nodejs/node/blob/main/test/parallel/test-webcrypto-encrypt-decrypt.js

// Test Encrypt/Decrypt RSA-OAEP
test(SUITE, 'RSA-OAEP', async () => {
  const buf = getRandomValues(new Uint8Array(50));
  const ec = new TextEncoder();
  const keyPair = (await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    false,
    ['encrypt', 'decrypt'],
  )) as TestCryptoKeyPair;

  const ciphertext = await subtle.encrypt(
    {
      name: 'RSA-OAEP',
      label: ec.encode('a label'),
    } as RsaOaepParams,
    keyPair.publicKey,
    buf,
  );

  const plaintext = await subtle.decrypt(
    {
      name: 'RSA-OAEP',
      label: ec.encode('a label'),
    } as RsaOaepParams,
    keyPair.privateKey,
    ciphertext,
  );

  expect(Buffer.from(plaintext).toString('hex')).to.equal(
    Buffer.from(buf as Uint8Array).toString('hex'),
  );
});

// from https://github.com/nodejs/node/blob/main/test/parallel/test-webcrypto-encrypt-decrypt-rsa.js
async function importRSAVectorKey(
  publicKeyBuffer: ArrayBuffer,
  _privateKeyBuffer: ArrayBuffer | null,
  name: AnyAlgorithm,
  hash: DigestAlgorithm,
  publicUsages: KeyUsage[],
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _privateUsages: KeyUsage[],
): Promise<TestCryptoKeyPair> {
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

  return { publicKey, privateKey: publicKey }; // Using publicKey as placeholder since privateKey import is commented out
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
    ciphercopy[0] = 255 - ciphercopy[0]!;

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
    plaintext = bufferLikeToArrayBuffer(plaintextCopy);
  }

  const result = await subtle.encrypt(
    algorithm,
    publicKey as CryptoKey,
    plaintext,
  );
  if (modify) {
    const plaintextView = new Uint8Array(plaintext);
    plaintextView[0] = 255 - plaintextView[0]!;
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
  newplaintext.set(new Uint8Array(plaintext), 0);
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
    test(SUITE, `RSA-OAEP decryption ${vector.name}`, async () => {
      await testRSADecryption(vector);
    });
    test(SUITE, `RSA-OAEP decryption wrong key ${vector.name}`, async () => {
      await testRSADecryptionWrongKey(vector);
    });
    test(SUITE, `RSA-OAEP decryption bad usage ${vector.name}`, async () => {
      await testRSADecryptionBadUsage(vector);
    });
    test(SUITE, `RSA-OAEP encryption ${vector.name}`, async () => {
      await testRSAEncryption(vector);
    });
    test(SUITE, `RSA-OAEP encryption ${vector.name}`, async () => {
      await testRSAEncryption(vector, true);
    });
    test(
      SUITE,
      `RSA-OAEP encryption long plaintext ${vector.name}`,
      async () => {
        await testRSAEncryptionLongPlaintext(vector);
      },
    );
    test(SUITE, `RSA-OAEP encryption wrong key ${vector.name}`, async () => {
      await testRSAEncryptionWrongKey(vector);
    });
    test(SUITE, `RSA-OAEP encryption bad usage ${vector.name}`, async () => {
      await testRSAEncryptionBadUsage(vector);
    });
  });
}

// from https://github.com/nodejs/node/blob/main/test/parallel/test-webcrypto-encrypt-decrypt.js
// Test Encrypt/Decrypt AES-CTR
test(SUITE, 'AES-CTR', async () => {
  const buf = getRandomValues(new Uint8Array(50));
  const counter = getRandomValues(new Uint8Array(16));

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
    Buffer.from(buf as Uint8Array).toString('hex'),
  );
});

// Test Encrypt/Decrypt AES-CBC
test(SUITE, 'AES-CBC', async () => {
  const buf = getRandomValues(new Uint8Array(50));
  const iv = getRandomValues(new Uint8Array(16));

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
    Buffer.from(buf as Uint8Array).toString('hex'),
  );
});

// Test Encrypt/Decrypt AES-GCM
test(SUITE, 'AES-GCM', async () => {
  const buf = getRandomValues(new Uint8Array(50));
  const iv = getRandomValues(new Uint8Array(12));

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
    Buffer.from(buf as Uint8Array).toString('hex'),
  );
});

// Test Encrypt/Decrypt AES-GCM with iv & additionalData
// default AuthTag length
test(
  SUITE,
  'AES-GCM with iv & additionalData - default AuthTag length',
  async () => {
    const iv = getRandomValues(new Uint8Array(12));
    const aad = getRandomValues(new Uint8Array(32));

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
      getRandomValues(new Uint8Array(32)),
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
  },
);

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
  plaintextBuffer[0] = 255 - plaintextBuffer[0]!;

  expect(ab2str(output)).to.equal(ab2str(result), 'output != result');

  const checkAB = await subtle.decrypt(algorithm, key, output);
  // Converting the returned ArrayBuffer into a Buffer right away,
  // so that the next line works
  const check = Buffer.from(checkAB);
  check[0] = 255 - check[0]!;

  expect(ab2str(checkAB)).to.equal(
    plaintextBuffer.toString('hex'),
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
    test(SUITE, `testEncrypt passing ${name} ${keyLength}`, async () => {
      await testAESEncrypt(vector);
    });
    test(
      SUITE,
      `testEncryptNoEncrypt passing ${name} ${keyLength}`,
      async () => {
        await testAESEncryptNoEncrypt(vector);
      },
    );
    test(
      SUITE,
      `testEncryptNoDecrypt passing ${name} ${keyLength}`,
      async () => {
        await testAESEncryptNoDecrypt(vector);
      },
    );
    test(
      SUITE,
      `testEncryptWrongAlg passing ${name} ${keyLength}`,
      async () => {
        await testAESEncryptWrongAlg(vector, 'AES-CTR');
      },
    );
  });

  failing.forEach((vector: AesEncryptDecryptTestVector) => {
    const { algorithm, keyLength } = vector;
    const { name } = algorithm as AesCbcParams;
    test(SUITE, `testEncrypt failing cbc ${name} ${keyLength}`, async () => {
      await assertThrowsAsync(
        async () => await testAESEncrypt(vector),
        'algorithm.iv must contain exactly 16 bytes',
      );
    });
    test(SUITE, `testDecrypt failing cbc ${name} ${keyLength}`, async () => {
      await assertThrowsAsync(
        async () => await testAESDecrypt(vector),
        'algorithm.iv must contain exactly 16 bytes',
      );
    });
  });

  decryptionFailing.forEach((vector: AesEncryptDecryptTestVector) => {
    const { algorithm, keyLength } = vector;
    const { name } = algorithm as AesCbcParams;
    test(
      SUITE,
      `testDecrypt decryptionFailing ${name} ${keyLength}`,
      async () => {
        await assertThrowsAsync(
          async () => await testAESDecrypt(vector),
          'error in DoCipher, status: 2',
        );
      },
    );
  });
}

// Test aes-ctr vectors
{
  const { passing, failing, decryptionFailing } = aes_ctr_fixtures;

  passing.forEach((vector: AesEncryptDecryptTestVector) => {
    const { algorithm, keyLength } = vector;
    const { name } = algorithm as AesCtrParams;
    test(SUITE, `testEncrypt passing ${name} ${keyLength}`, async () => {
      await testAESEncrypt(vector);
    });
    test(
      SUITE,
      `testEncryptNoEncrypt passing ${name} ${keyLength}`,
      async () => {
        await testAESEncryptNoEncrypt(vector);
      },
    );
    test(
      SUITE,
      `testEncryptNoDecrypt passing ${name} ${keyLength}`,
      async () => {
        await testAESEncryptNoDecrypt(vector);
      },
    );
    test(
      SUITE,
      `testEncryptWrongAlg passing ${name} ${keyLength}`,
      async () => {
        await testAESEncryptWrongAlg(vector, 'AES-CBC');
      },
    );
  });

  // TODO(@jasnell): These fail for different reasons. Need to
  // make them consistent
  failing.forEach((vector: AesEncryptDecryptTestVector) => {
    const { algorithm, keyLength } = vector;
    const { name } = algorithm as AesCtrParams;
    test(SUITE, `testEncrypt failing ctr ${name} ${keyLength}`, async () => {
      await assertThrowsAsync(
        async () => await testAESEncrypt(vector),
        'AES-CTR algorithm.length must be between 1 and 128',
      );
    });
    test(SUITE, `testDecrypt failing ctr ${name} ${keyLength}`, async () => {
      await assertThrowsAsync(
        async () => await testAESDecrypt(vector),
        'AES-CTR algorithm.length must be between 1 and 128',
      );
    });
  });

  decryptionFailing.forEach((vector: AesEncryptDecryptTestVector) => {
    const { algorithm, keyLength } = vector;
    const { name } = algorithm as AesCtrParams;
    test(
      SUITE,
      `testDecrypt decryptionFailing ${name} ${keyLength}`,
      async () => {
        await assertThrowsAsync(
          async () => await testAESDecrypt(vector),
          'error in DoCipher, status: 2',
        );
      },
    );
  });
}

// Test aes-gcm vectors
{
  const { passing, failing, decryptionFailing } = aes_gcm_fixtures;

  passing.forEach((vector: AesEncryptDecryptTestVector) => {
    const { algorithm, keyLength } = vector;
    const { name, tagLength } = algorithm as AesGcmParams;
    test(
      SUITE,
      `testEncrypt passing ${name} ${keyLength} ${tagLength}`,
      async () => {
        await testAESEncrypt(vector);
      },
    );
    test(
      SUITE,
      `testEncryptNoEncrypt passing ${name} ${keyLength} ${tagLength}`,
      async () => {
        await testAESEncryptNoEncrypt(vector);
      },
    );
    test(
      SUITE,
      `testEncryptNoDecrypt passing ${name} ${keyLength} ${tagLength}`,
      async () => {
        await testAESEncryptNoDecrypt(vector);
      },
    );
    test(
      SUITE,
      `testEncryptWrongAlg passing ${name} ${keyLength} ${tagLength}`,
      async () => {
        await testAESEncryptWrongAlg(vector, 'AES-CBC');
      },
    );
  });

  failing.forEach((vector: AesEncryptDecryptTestVector) => {
    const { algorithm, keyLength } = vector;
    const { name, tagLength } = algorithm as AesGcmParams;
    test(
      SUITE,
      `testEncrypt failing gcm ${name} ${keyLength} ${tagLength}`,
      async () => {
        await assertThrowsAsync(
          async () => await testAESEncrypt(vector),
          'is not a valid AES-GCM tag length',
        );
      },
    );
    test(
      SUITE,
      `testDecrypt failing gcm ${name} ${keyLength} ${tagLength}`,
      async () => {
        await assertThrowsAsync(
          async () => await testAESDecrypt(vector),
          'is not a valid AES-GCM tag length',
        );
      },
    );
  });

  decryptionFailing.forEach((vector: AesEncryptDecryptTestVector) => {
    const { algorithm, keyLength } = vector;
    const { name, tagLength } = algorithm as AesGcmParams;
    test(
      SUITE,
      `testDecrypt decryptionFailing ${name} ${keyLength} ${tagLength}`,
      async () => {
        await assertThrowsAsync(
          async () => await testAESDecrypt(vector),
          'error in DoCipher, status: 2',
        );
      },
    );
  });
}
