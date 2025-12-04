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
  publicKeyBuffer: Uint8Array;
  publicKeyFormat: string;
  privateKey: Buffer | null;
  privateKeyBuffer: Uint8Array | null;
  privateKeyFormat: string | null;
  algorithm: RsaOaepParams;
  hash: DigestAlgorithm;
  plaintext: Uint8Array;
  ciphertext: Uint8Array;
};

export type AesEncryptDecryptTestVector = {
  keyBuffer?: Uint8Array;
  algorithm?: EncryptDecryptParams;
  plaintext?: Uint8Array;
  result?: Uint8Array;
  keyLength?: string;
};

export type VectorValue = Record<string, Uint8Array>;
export type BadPadding = {
  zeroPadChar: Uint8Array;
  bigPadChar: Uint8Array;
  inconsistentPadChars: Uint8Array;
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
  publicKeyBuffer: Uint8Array,
  privateKeyBuffer: Uint8Array | null,
  name: AnyAlgorithm,
  hash: DigestAlgorithm,
  publicUsages: KeyUsage[],
  privateUsages: KeyUsage[],
): Promise<TestCryptoKeyPair> {
  const publicKey = await subtle.importKey(
    'spki',
    publicKeyBuffer,
    { name, hash },
    false,
    publicUsages,
  );

  let privateKey: CryptoKey | undefined;
  if (privateKeyBuffer !== null) {
    privateKey = await subtle.importKey(
      'pkcs8',
      privateKeyBuffer,
      { name, hash },
      false,
      privateUsages,
    );
  }

  return { publicKey, privateKey: privateKey || publicKey };
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
  const plaintextToEncrypt = modify
    ? bufferLikeToArrayBuffer(plaintextCopy)
    : plaintext;

  const result = await subtle.encrypt(
    algorithm,
    publicKey as CryptoKey,
    plaintextToEncrypt,
  );
  if (modify) {
    const plaintextView = new Uint8Array(plaintext);
    plaintextView[0] = 255 - plaintextView[0]!;
  }
  expect(result.byteLength).to.be.greaterThan(0);

  // TODO: remove condition when importKey() rsa pkcs8 is implemented
  if (privateKey !== undefined) {
    const encodedPlaintext = Buffer.from(plaintextCopy).toString('hex');

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
    'data too large for key size',
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
    'The requested operation is not valid for the provided key',
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

// Test ChaCha20-Poly1305
test(SUITE, 'ChaCha20-Poly1305', async () => {
  const buf = getRandomValues(new Uint8Array(50));
  const iv = getRandomValues(new Uint8Array(12)); // 96-bit nonce

  const key = await subtle.generateKey(
    {
      name: 'ChaCha20-Poly1305',
      length: 256,
    } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    true,
    ['encrypt', 'decrypt'],
  );

  const ciphertext = await subtle.encrypt(
    { name: 'ChaCha20-Poly1305', iv } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    key as CryptoKey,
    buf,
  );

  const plaintext = await subtle.decrypt(
    { name: 'ChaCha20-Poly1305', iv } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    key as CryptoKey,
    ciphertext,
  );

  expect(Buffer.from(plaintext).toString('hex')).to.equal(
    Buffer.from(buf as Uint8Array).toString('hex'),
  );
});

// Test ChaCha20-Poly1305 with AAD
test(SUITE, 'ChaCha20-Poly1305 with AAD', async () => {
  const plaintext = getRandomValues(new Uint8Array(32));
  const iv = getRandomValues(new Uint8Array(12));
  const aad = getRandomValues(new Uint8Array(16));

  const key = await subtle.generateKey(
    { name: 'ChaCha20-Poly1305', length: 256 } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    true,
    ['encrypt', 'decrypt'],
  );

  const ciphertext = await subtle.encrypt(
    { name: 'ChaCha20-Poly1305', iv, additionalData: aad } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    key as CryptoKey,
    plaintext,
  );

  const decrypted = await subtle.decrypt(
    { name: 'ChaCha20-Poly1305', iv, additionalData: aad } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    key as CryptoKey,
    ciphertext,
  );

  expect(Buffer.from(decrypted).toString('hex')).to.equal(
    Buffer.from(plaintext as Uint8Array).toString('hex'),
  );
});

// RFC 8439 test vector for ChaCha20-Poly1305
test(SUITE, 'ChaCha20-Poly1305 RF C 8439 vector', async () => {
  const keyHex =
    '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f';
  const nonceHex = '070000004041424344454647';
  const plaintextHex =
    '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e';
  const aadHex = '50515253c0c1c2c3c4c5c6c7';
  const expectedCiphertextHex =
    'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116';
  const expectedTagHex = '1ae10b594f09e26a7e902ecbd0600691';

  const key = await subtle.importKey(
    'raw',
    Buffer.from(keyHex, 'hex'),
    { name: 'ChaCha20-Poly1305' } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    true,
    ['encrypt', 'decrypt'],
  );

  const ciphertext = await subtle.encrypt(
    {
      name: 'ChaCha20-Poly1305',
      iv: Buffer.from(nonceHex, 'hex'),
      additionalData: Buffer.from(aadHex, 'hex'),
    } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    key as CryptoKey,
    Buffer.from(plaintextHex, 'hex'),
  );

  // Ciphertext includes tag at the end (last 16 bytes)
  const ctWithTag = Buffer.from(ciphertext);
  const ct = ctWithTag.subarray(0, -16);
  const tag = ctWithTag.subarray(-16);

  expect(ct.toString('hex')).to.equal(expectedCiphertextHex);
  expect(tag.toString('hex')).to.equal(expectedTagHex);
});

// ChaCha20-Poly1305 comprehensive tests (similar to AES)
test(SUITE, 'ChaCha20-Poly1305 wrong key usage encrypt', async () => {
  const key = await subtle.generateKey(
    { name: 'ChaCha20-Poly1305', length: 256 } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    true,
    ['decrypt'], // Only decrypt, not encrypt
  );

  await assertThrowsAsync(
    async () =>
      await subtle.encrypt(
        {
          name: 'ChaCha20-Poly1305',
          iv: getRandomValues(new Uint8Array(12)),
        } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
        key as CryptoKey,
        getRandomValues(new Uint8Array(32)),
      ),
    'The requested operation is not valid for the provided key',
  );
});

test(SUITE, 'ChaCha20-Poly1305 wrong key usage decrypt', async () => {
  const key = await subtle.generateKey(
    { name: 'ChaCha20-Poly1305', length: 256 } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    true,
    ['encrypt'], // Only encrypt, not decrypt
  );

  const iv = getRandomValues(new Uint8Array(12));
  const plaintext = getRandomValues(new Uint8Array(32));

  const ciphertext = await subtle.encrypt(
    { name: 'ChaCha20-Poly1305', iv } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    key as CryptoKey,
    plaintext,
  );

  await assertThrowsAsync(
    async () =>
      await subtle.decrypt(
        { name: 'ChaCha20-Poly1305', iv } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
        key as CryptoKey,
        ciphertext,
      ),
    'The requested operation is not valid for the provided key',
  );
});

test(SUITE, 'ChaCha20-Poly1305 invalid IV length', async () => {
  const key = await subtle.generateKey(
    { name: 'ChaCha20-Poly1305', length: 256 } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    true,
    ['encrypt', 'decrypt'],
  );

  // Test with wrong IV lengths
  const invalidIVs = [
    getRandomValues(new Uint8Array(8)), // Too short
    getRandomValues(new Uint8Array(16)), // Too long
    getRandomValues(new Uint8Array(24)), // Way too long
  ];

  for (const iv of invalidIVs) {
    await assertThrowsAsync(
      async () =>
        await subtle.encrypt(
          { name: 'ChaCha20-Poly1305', iv } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
          key as CryptoKey,
          getRandomValues(new Uint8Array(32)),
        ),
      'ChaCha20-Poly1305 IV must be exactly 12 bytes',
    );
  }
});

test(SUITE, 'ChaCha20-Poly1305 empty plaintext', async () => {
  const key = await subtle.generateKey(
    { name: 'ChaCha20-Poly1305', length: 256 } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    true,
    ['encrypt', 'decrypt'],
  );

  const iv = getRandomValues(new Uint8Array(12));
  const plaintext = new Uint8Array(0); // Empty

  const ciphertext = await subtle.encrypt(
    { name: 'ChaCha20-Poly1305', iv } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    key as CryptoKey,
    plaintext,
  );

  // Should still include auth tag (16 bytes)
  expect(ciphertext.byteLength).to.equal(16);

  const decrypted = await subtle.decrypt(
    { name: 'ChaCha20-Poly1305', iv } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    key as CryptoKey,
    ciphertext,
  );

  expect(decrypted.byteLength).to.equal(0);
});

test(SUITE, 'ChaCha20-Poly1305 large plaintext', async () => {
  const key = await subtle.generateKey(
    { name: 'ChaCha20-Poly1305', length: 256 } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    true,
    ['encrypt', 'decrypt'],
  );

  const iv = getRandomValues(new Uint8Array(12));
  const plaintext = getRandomValues(new Uint8Array(1024 * 64)); // 64KB

  const ciphertext = await subtle.encrypt(
    { name: 'ChaCha20-Poly1305', iv } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    key as CryptoKey,
    plaintext,
  );

  // Ciphertext = plaintext + 16-byte tag
  expect(ciphertext.byteLength).to.equal(plaintext.byteLength + 16);

  const decrypted = await subtle.decrypt(
    { name: 'ChaCha20-Poly1305', iv } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    key as CryptoKey,
    ciphertext,
  );

  expect(Buffer.from(decrypted).toString('hex')).to.equal(
    Buffer.from(plaintext as Uint8Array).toString('hex'),
  );
});

test(SUITE, 'ChaCha20-Poly1305 key import/export raw', async () => {
  const keyMaterial = getRandomValues(new Uint8Array(32)); // 256 bits

  const key = await subtle.importKey(
    'raw',
    keyMaterial,
    { name: 'ChaCha20-Poly1305' } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    true,
    ['encrypt', 'decrypt'],
  );

  const exported = await subtle.exportKey('raw', key as CryptoKey);

  expect(Buffer.from(exported as ArrayBuffer).toString('hex')).to.equal(
    Buffer.from(keyMaterial as Uint8Array).toString('hex'),
  );
});

test(SUITE, 'ChaCha20-Poly1305 tampered ciphertext', async () => {
  const key = await subtle.generateKey(
    { name: 'ChaCha20-Poly1305', length: 256 } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    true,
    ['encrypt', 'decrypt'],
  );

  const iv = getRandomValues(new Uint8Array(12));
  const plaintext = getRandomValues(new Uint8Array(32));

  const ciphertext = await subtle.encrypt(
    { name: 'ChaCha20-Poly1305', iv } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    key as CryptoKey,
    plaintext,
  );

  // Tamper with the ciphertext
  const tamperedCiphertext = new Uint8Array(ciphertext);
  tamperedCiphertext[0]! ^= 1; // Flip a bit

  await assertThrowsAsync(
    async () =>
      await subtle.decrypt(
        { name: 'ChaCha20-Poly1305', iv } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
        key as CryptoKey,
        tamperedCiphertext,
      ),
    'Failed to finalize',
  );
});

test(SUITE, 'ChaCha20-Poly1305 tampered tag', async () => {
  const key = await subtle.generateKey(
    { name: 'ChaCha20-Poly1305', length: 256 } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    true,
    ['encrypt', 'decrypt'],
  );

  const iv = getRandomValues(new Uint8Array(12));
  const plaintext = getRandomValues(new Uint8Array(32));

  const ciphertext = await subtle.encrypt(
    { name: 'ChaCha20-Poly1305', iv } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    key as CryptoKey,
    plaintext,
  );

  // Tamper with the auth tag (last 16 bytes)
  const tamperedCiphertext = new Uint8Array(ciphertext);
  tamperedCiphertext[tamperedCiphertext.length - 1]! ^= 1; // Flip a bit in tag

  await assertThrowsAsync(
    async () =>
      await subtle.decrypt(
        { name: 'ChaCha20-Poly1305', iv } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
        key as CryptoKey,
        tamperedCiphertext,
      ),
    'Failed to finalize',
  );
});

test(SUITE, 'ChaCha20-Poly1305 wrong AAD', async () => {
  const key = await subtle.generateKey(
    { name: 'ChaCha20-Poly1305', length: 256 } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    true,
    ['encrypt', 'decrypt'],
  );

  const iv = getRandomValues(new Uint8Array(12));
  const plaintext = getRandomValues(new Uint8Array(32));
  const aad1 = getRandomValues(new Uint8Array(16));
  const aad2 = getRandomValues(new Uint8Array(16));

  const ciphertext = await subtle.encrypt(
    { name: 'ChaCha20-Poly1305', iv, additionalData: aad1 } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
    key as CryptoKey,
    plaintext,
  );

  // Try to decrypt with different AAD
  await assertThrowsAsync(
    async () =>
      await subtle.decrypt(
        { name: 'ChaCha20-Poly1305', iv, additionalData: aad2 } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
        key as CryptoKey,
        ciphertext,
      ),
    'Failed to finalize',
  );
});

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

  expect(ab2str(output)).to.equal(
    ab2str(result.buffer as ArrayBuffer),
    'output != result',
  );

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
          'bad decrypt',
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
          'bad decrypt',
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
          'bad decrypt',
        );
      },
    );
  });
}
