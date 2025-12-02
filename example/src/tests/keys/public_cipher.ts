import { Buffer } from '@craftzdog/react-native-buffer';
import {
  publicEncrypt,
  publicDecrypt,
  generateKeyPair,
  createPrivateKey,
  createPublicKey,
  subtle,
  isCryptoKeyPair,
} from 'react-native-quick-crypto';
import type { WebCryptoKeyPair } from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test, assertThrowsAsync, decodeHex } from '../util';

const SUITE = 'keys.publicEncrypt/publicDecrypt';

// RSA 2048-bit test keys from fixtures
// Source: Node.js test fixtures / WebCrypto test vectors
const pkcs8 = decodeHex(
  '308204bf020100300d06092a864886f70d0101010500048204a930820' +
    '4a50201000282010100d3576092e62957364544e7e4233b7bdb293db2' +
    '085122c479328546f9f0f712f657c4b17868c930908cc594f7ed00c01' +
    '442c1af04c2f678a48ba2c80fd1713e30b5ac50787ac3516589f17196' +
    '7f6386ada34900a6bb04eecea42bf043ced9a0f94d0cc09e919b9d716' +
    '6c08ab6ce204640aea4c4920db6d86eb916d0dcc0f4341a10380429e7' +
    'e1032144ea949de8f6c0ccbf95fa8e928d70d8a38ce168db45f6f1346' +
    '63d6f656f5ceabc725da8c02aabeaaa13ac36a75cc0bae135df3114b6' +
    '6589c7ed3cb61559ae5a384f162bfa80dbe4617f86c3f1d010c94fe2c' +
    '9bf019a6e63b3efc028d43cee611c85ec263c906c463772c6911b19ee' +
    'c096ca76ec5e31e1e3020301000102820101008b375ccb87c825c5ff3' +
    'd53d009916e9641057e18527227a07ab226be1088813a3b38bb7b48f3' +
    '77055165fa2a9339d24dc667d5c5ba3427e6a481176eac15ffd490683' +
    '11e1c283b9f3a8e0cb809b4630c50aa8f3e45a60b359e19bf8cbb5eca' +
    'd64e761f1095743ff36aaf5cf0ecb97fedaddda60b5bf35d811a75b82' +
    '2230cfaa0192fad40547e275448aa3316bf8e2b4ce0854fc7708b537b' +
    'a22d13210b09aec37a2759efc082a1531b23a91730037dde4ef26b5f9' +
    '6efdcc39fd34c345ad51cbbe44fe58b8a3b4ec997866c086dff1b8831' +
    'ef0a1fea263cf7dacd03c04cbcc2b279e57fa5b953996bfb1dd68817a' +
    'f7fb42cdef7a5294a57fac2b8ad739f1b029902818100fbf833c2c631' +
    'c970240c8e7485f06a3ea2a84822511a8627dd464ef8afaf7148d1a42' +
    '5b6b8657ddd5246832b8e533020c5bbb568855a6aec3e4221d793f1dc' +
    '5b2f2584e2415e48e9a2bd292b134031f99c8eb42fc0bcd0449bf22ce' +
    '6dec97014efe5ac93ebe835877656252cbbb16c415b67b184d2284568' +
    'a277d59335585cfd02818100d6b8ce27c7295d5d16fc3570ed64c8da9' +
    '303fad29488c1a65e9ad711f90370187dbbfd81316d69648bc88cc5c8' +
    '3551afff45debacfb61105f709e4c30809b90031ebd686244496c6f69' +
    'e692ebdc814f64239f4ad15756ecb78c5a5b09931db183077c546a38c' +
    '4c743889ad3d3ed079b5622ed0120fa0e1f93b593db7d852e05f02818' +
    '038874b9d83f78178ce2d9efc175c83897fd67f306bbfa69f64ee3423' +
    '68ced47c80c3f1ce177a758d64bafb0c9786a44285fa01cdec3507cde' +
    'e7dc9b7e2b21d3cbbcc100eee9967843b057329fdcca62998ed0f11b3' +
    '8ce8b0abc7de39017c71cfd0ae57546c559144cdd0afd0645f7ea8ff0' +
    '7b974d1ed44fd1f8e00f560bf6d45028181008529ef9073cf8f7b5ff9' +
    'e21abadf3a4173d3900670dfaf59426abcdf0493c13d2f1d1b46b824a' +
    '6ac1894b3d925250c181e3472c16078056eb19a8d28f71f3080927534' +
    '81d49444fdf78c9ea6c24407dc018e77d3afef385b2ff7439e9623794' +
    '1332dd446cebeffdb4404fe4f71595161d016402c334d0f57c61abe4f' +
    'f9f4cbf90281810087d87708d46763e4ccbeb2d1e9712e5bf0216d70d' +
    'e9420a5b2069b7459b99f5d9f7f2fad7cd79aaee67a7f9a34437e3c79' +
    'a84af0cd8de9dff268eb0c4793f501f988d540f6d3475c2079b8227a2' +
    '3d968dec4e3c66503187193459630472bfdb6ba1de786c797fa6f4ea6' +
    '5a2a8419262f29678856cb73c9bd4bc89b5e041b2277',
);

const spki = decodeHex(
  '30820122300d06092a864886f70d01010105000382010f003082010a0' +
    '282010100d3576092e62957364544e7e4233b7bdb293db2085122c479' +
    '328546f9f0f712f657c4b17868c930908cc594f7ed00c01442c1af04c' +
    '2f678a48ba2c80fd1713e30b5ac50787ac3516589f171967f6386ada3' +
    '4900a6bb04eecea42bf043ced9a0f94d0cc09e919b9d7166c08ab6ce2' +
    '04640aea4c4920db6d86eb916d0dcc0f4341a10380429e7e1032144ea' +
    '949de8f6c0ccbf95fa8e928d70d8a38ce168db45f6f134663d6f656f5' +
    'ceabc725da8c02aabeaaa13ac36a75cc0bae135df3114b66589c7ed3c' +
    'b61559ae5a384f162bfa80dbe4617f86c3f1d010c94fe2c9bf019a6e6' +
    '3b3efc028d43cee611c85ec263c906c463772c6911b19eec096ca76ec' +
    '5e31e1e30203010001',
);

const label = decodeHex(
  '5468657265206172652037206675727468657220656469746f7269616' +
    'c206e6f74657320696e2074686520646f63756d656e742e',
);

// Test plaintext values
const shortPlaintext = Buffer.from('Hello, World!');
const testMessage = Buffer.from('Test message for RSA encryption');

// --- Basic Encrypt/Decrypt Tests ---

test(SUITE, 'publicEncrypt/publicDecrypt round-trip with DER keys', () => {
  const publicKey = createPublicKey({
    key: Buffer.from(spki),
    format: 'der',
    type: 'spki',
  });

  const privateKey = createPrivateKey({
    key: Buffer.from(pkcs8),
    format: 'der',
    type: 'pkcs8',
  });

  const encrypted = publicEncrypt(publicKey, shortPlaintext);
  const decrypted = publicDecrypt(privateKey, encrypted);

  expect(decrypted.toString()).to.equal(shortPlaintext.toString());
});

test(SUITE, 'publicEncrypt/publicDecrypt with KeyObject', () => {
  const publicKey = createPublicKey({
    key: Buffer.from(spki),
    format: 'der',
    type: 'spki',
  });

  const privateKey = createPrivateKey({
    key: Buffer.from(pkcs8),
    format: 'der',
    type: 'pkcs8',
  });

  const encrypted = publicEncrypt(publicKey, testMessage);
  const decrypted = publicDecrypt(privateKey, encrypted);

  expect(Buffer.compare(decrypted, testMessage)).to.equal(0);
});

// --- OAEP Hash Algorithm Tests ---

test(SUITE, 'publicEncrypt/publicDecrypt with SHA-1 hash', () => {
  const publicKey = createPublicKey({
    key: Buffer.from(spki),
    format: 'der',
    type: 'spki',
  });

  const privateKey = createPrivateKey({
    key: Buffer.from(pkcs8),
    format: 'der',
    type: 'pkcs8',
  });

  const encrypted = publicEncrypt(
    { key: publicKey, oaepHash: 'SHA-1' },
    shortPlaintext,
  );
  const decrypted = publicDecrypt(
    { key: privateKey, oaepHash: 'SHA-1' },
    encrypted,
  );

  expect(decrypted.toString()).to.equal(shortPlaintext.toString());
});

test(SUITE, 'publicEncrypt/publicDecrypt with SHA-256 hash', () => {
  const publicKey = createPublicKey({
    key: Buffer.from(spki),
    format: 'der',
    type: 'spki',
  });

  const privateKey = createPrivateKey({
    key: Buffer.from(pkcs8),
    format: 'der',
    type: 'pkcs8',
  });

  const encrypted = publicEncrypt(
    { key: publicKey, oaepHash: 'SHA-256' },
    shortPlaintext,
  );
  const decrypted = publicDecrypt(
    { key: privateKey, oaepHash: 'SHA-256' },
    encrypted,
  );

  expect(decrypted.toString()).to.equal(shortPlaintext.toString());
});

test(SUITE, 'publicEncrypt/publicDecrypt with SHA-384 hash', () => {
  const publicKey = createPublicKey({
    key: Buffer.from(spki),
    format: 'der',
    type: 'spki',
  });

  const privateKey = createPrivateKey({
    key: Buffer.from(pkcs8),
    format: 'der',
    type: 'pkcs8',
  });

  const encrypted = publicEncrypt(
    { key: publicKey, oaepHash: 'SHA-384' },
    shortPlaintext,
  );
  const decrypted = publicDecrypt(
    { key: privateKey, oaepHash: 'SHA-384' },
    encrypted,
  );

  expect(decrypted.toString()).to.equal(shortPlaintext.toString());
});

test(SUITE, 'publicEncrypt/publicDecrypt with SHA-512 hash', () => {
  const publicKey = createPublicKey({
    key: Buffer.from(spki),
    format: 'der',
    type: 'spki',
  });

  const privateKey = createPrivateKey({
    key: Buffer.from(pkcs8),
    format: 'der',
    type: 'pkcs8',
  });

  const encrypted = publicEncrypt(
    { key: publicKey, oaepHash: 'SHA-512' },
    shortPlaintext,
  );
  const decrypted = publicDecrypt(
    { key: privateKey, oaepHash: 'SHA-512' },
    encrypted,
  );

  expect(decrypted.toString()).to.equal(shortPlaintext.toString());
});

// --- OAEP Label Tests ---

test(SUITE, 'publicEncrypt/publicDecrypt with OAEP label', () => {
  const publicKey = createPublicKey({
    key: Buffer.from(spki),
    format: 'der',
    type: 'spki',
  });

  const privateKey = createPrivateKey({
    key: Buffer.from(pkcs8),
    format: 'der',
    type: 'pkcs8',
  });

  const encrypted = publicEncrypt(
    { key: publicKey, oaepHash: 'SHA-256', oaepLabel: label },
    shortPlaintext,
  );
  const decrypted = publicDecrypt(
    { key: privateKey, oaepHash: 'SHA-256', oaepLabel: label },
    encrypted,
  );

  expect(decrypted.toString()).to.equal(shortPlaintext.toString());
});

test(SUITE, 'Decrypt fails with wrong OAEP label', async () => {
  const publicKey = createPublicKey({
    key: Buffer.from(spki),
    format: 'der',
    type: 'spki',
  });

  const privateKey = createPrivateKey({
    key: Buffer.from(pkcs8),
    format: 'der',
    type: 'pkcs8',
  });

  const encrypted = publicEncrypt(
    { key: publicKey, oaepHash: 'SHA-256', oaepLabel: label },
    shortPlaintext,
  );

  const wrongLabel = Buffer.from('wrong label');

  await assertThrowsAsync(async () => {
    publicDecrypt(
      { key: privateKey, oaepHash: 'SHA-256', oaepLabel: wrongLabel },
      encrypted,
    );
  }, 'publicDecrypt failed');
});

// --- generateKeyPair Integration Tests ---

test(
  SUITE,
  'publicEncrypt/publicDecrypt with generateKeyPair RSA',
  async () => {
    const { privateKey, publicKey } = await new Promise<{
      privateKey: string;
      publicKey: string;
    }>((resolve, reject) => {
      generateKeyPair(
        'rsa',
        {
          modulusLength: 2048,
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        },
        (err, pubKey, privKey) => {
          if (err) reject(err);
          else
            resolve({
              privateKey: privKey as string,
              publicKey: pubKey as string,
            });
        },
      );
    });

    const pubKeyObj = createPublicKey(publicKey);
    const privKeyObj = createPrivateKey(privateKey);

    const encrypted = publicEncrypt(pubKeyObj, testMessage);
    const decrypted = publicDecrypt(privKeyObj, encrypted);

    expect(Buffer.compare(decrypted, testMessage)).to.equal(0);
  },
);

// --- WebCrypto Compatibility Tests ---

test(SUITE, 'publicEncrypt compatible with subtle.decrypt', async () => {
  // Import keys for WebCrypto
  const cryptoKeyPair = await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  );
  if (!isCryptoKeyPair(cryptoKeyPair)) throw new Error('Expected key pair');
  const keyPair = cryptoKeyPair as WebCryptoKeyPair;

  // Export public key for publicEncrypt
  const publicKeySpki = await subtle.exportKey('spki', keyPair.publicKey);
  const publicKeyObj = createPublicKey({
    key: Buffer.from(publicKeySpki as ArrayBuffer),
    format: 'der',
    type: 'spki',
  });

  // Encrypt with publicEncrypt
  const encrypted = publicEncrypt(
    { key: publicKeyObj, oaepHash: 'SHA-256' },
    shortPlaintext,
  );

  // Decrypt with subtle.decrypt
  const decrypted = await subtle.decrypt(
    { name: 'RSA-OAEP' },
    keyPair.privateKey,
    encrypted,
  );

  expect(Buffer.from(decrypted).toString()).to.equal(shortPlaintext.toString());
});

test(SUITE, 'subtle.encrypt compatible with publicDecrypt', async () => {
  // Import keys for WebCrypto
  const cryptoKeyPair = await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  );
  if (!isCryptoKeyPair(cryptoKeyPair)) throw new Error('Expected key pair');
  const keyPair = cryptoKeyPair as WebCryptoKeyPair;

  // Encrypt with subtle.encrypt
  const encrypted = await subtle.encrypt(
    { name: 'RSA-OAEP' },
    keyPair.publicKey,
    shortPlaintext,
  );

  // Export private key for publicDecrypt
  const privateKeyPkcs8 = await subtle.exportKey('pkcs8', keyPair.privateKey);
  const privateKeyObj = createPrivateKey({
    key: Buffer.from(privateKeyPkcs8 as ArrayBuffer),
    format: 'der',
    type: 'pkcs8',
  });

  // Decrypt with publicDecrypt
  const decrypted = publicDecrypt(
    { key: privateKeyObj, oaepHash: 'SHA-256' },
    Buffer.from(encrypted),
  );

  expect(decrypted.toString()).to.equal(shortPlaintext.toString());
});

// --- Error Cases ---

test(SUITE, 'Decrypt fails with wrong hash algorithm', async () => {
  const publicKey = createPublicKey({
    key: Buffer.from(spki),
    format: 'der',
    type: 'spki',
  });

  const privateKey = createPrivateKey({
    key: Buffer.from(pkcs8),
    format: 'der',
    type: 'pkcs8',
  });

  const encrypted = publicEncrypt(
    { key: publicKey, oaepHash: 'SHA-256' },
    shortPlaintext,
  );

  await assertThrowsAsync(async () => {
    publicDecrypt({ key: privateKey, oaepHash: 'SHA-1' }, encrypted);
  }, 'publicDecrypt failed');
});

test(SUITE, 'publicEncrypt throws with invalid key', async () => {
  await assertThrowsAsync(async () => {
    publicEncrypt('not a valid key', shortPlaintext);
  }, '');
});

// --- Different Key Sizes ---

test(SUITE, 'publicEncrypt/publicDecrypt with 4096-bit RSA', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'rsa',
      {
        modulusLength: 4096,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      },
      (err, pubKey, privKey) => {
        if (err) reject(err);
        else
          resolve({
            privateKey: privKey as string,
            publicKey: pubKey as string,
          });
      },
    );
  });

  const pubKeyObj = createPublicKey(publicKey);
  const privKeyObj = createPrivateKey(privateKey);

  const encrypted = publicEncrypt(pubKeyObj, testMessage);
  const decrypted = publicDecrypt(privKeyObj, encrypted);

  expect(Buffer.compare(decrypted, testMessage)).to.equal(0);
});

// --- Empty and Edge Case Plaintexts ---

test(SUITE, 'publicEncrypt/publicDecrypt with empty plaintext', () => {
  const publicKey = createPublicKey({
    key: Buffer.from(spki),
    format: 'der',
    type: 'spki',
  });

  const privateKey = createPrivateKey({
    key: Buffer.from(pkcs8),
    format: 'der',
    type: 'pkcs8',
  });

  const emptyBuffer = Buffer.from('');
  const encrypted = publicEncrypt(publicKey, emptyBuffer);
  const decrypted = publicDecrypt(privateKey, encrypted);

  expect(decrypted.length).to.equal(0);
});

test(SUITE, 'publicEncrypt/publicDecrypt with single byte plaintext', () => {
  const publicKey = createPublicKey({
    key: Buffer.from(spki),
    format: 'der',
    type: 'spki',
  });

  const privateKey = createPrivateKey({
    key: Buffer.from(pkcs8),
    format: 'der',
    type: 'pkcs8',
  });

  const singleByte = Buffer.from([0x42]);
  const encrypted = publicEncrypt(publicKey, singleByte);
  const decrypted = publicDecrypt(privateKey, encrypted);

  expect(decrypted.length).to.equal(1);
  expect(decrypted[0]).to.equal(0x42);
});

// --- Maximum Plaintext Size Tests ---

test(SUITE, 'publicEncrypt with max size plaintext for SHA-256', () => {
  const publicKey = createPublicKey({
    key: Buffer.from(spki),
    format: 'der',
    type: 'spki',
  });

  const privateKey = createPrivateKey({
    key: Buffer.from(pkcs8),
    format: 'der',
    type: 'pkcs8',
  });

  // For RSA-OAEP with SHA-256: max = keySize - 2*hashSize - 2 = 256 - 64 - 2 = 190 bytes
  const maxPlaintext = Buffer.alloc(190, 'A');
  const encrypted = publicEncrypt(
    { key: publicKey, oaepHash: 'SHA-256' },
    maxPlaintext,
  );
  const decrypted = publicDecrypt(
    { key: privateKey, oaepHash: 'SHA-256' },
    encrypted,
  );

  expect(Buffer.compare(decrypted, maxPlaintext)).to.equal(0);
});

test(SUITE, 'publicEncrypt fails with oversized plaintext', async () => {
  const publicKey = createPublicKey({
    key: Buffer.from(spki),
    format: 'der',
    type: 'spki',
  });

  // For RSA-OAEP with SHA-256: max = 190 bytes, try 191
  const oversizedPlaintext = Buffer.alloc(191, 'A');

  await assertThrowsAsync(async () => {
    publicEncrypt({ key: publicKey, oaepHash: 'SHA-256' }, oversizedPlaintext);
  }, '');
});
