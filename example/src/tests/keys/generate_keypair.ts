import {
  generateKeyPair,
  generateKeyPairSync,
  createSign,
  createVerify,
  createPrivateKey,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test, assertThrowsAsync } from '../util';

const SUITE = 'keys.generateKeyPair';

// --- RSA Key Generation Tests ---

test(SUITE, 'generateKeyPair RSA 2048-bit with PEM encoding', async () => {
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

  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);
});

test(SUITE, 'generateKeyPair RSA 4096-bit', async () => {
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

  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);
});

test(SUITE, 'generateKeyPair RSA with DER encoding', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: ArrayBuffer;
    publicKey: ArrayBuffer;
  }>((resolve, reject) => {
    generateKeyPair(
      'rsa',
      {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      },
      (err, pubKey, privKey) => {
        if (err) reject(err);
        else
          resolve({
            privateKey: privKey as ArrayBuffer,
            publicKey: pubKey as ArrayBuffer,
          });
      },
    );
  });

  expect(privateKey instanceof ArrayBuffer).to.equal(true);
  expect(publicKey instanceof ArrayBuffer).to.equal(true);
  expect(privateKey.byteLength).to.be.greaterThan(0);
  expect(publicKey.byteLength).to.be.greaterThan(0);
});

test(SUITE, 'generateKeyPair RSA keys work for signing', async () => {
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

  const testData = 'Test data for signing';
  const signature = createSign('SHA256').update(testData).sign(privateKey);
  const isValid = createVerify('SHA256')
    .update(testData)
    .verify(publicKey, signature);

  expect(isValid).to.equal(true);
});

// --- RSA-PSS Key Generation Tests ---

test(SUITE, 'generateKeyPair RSA-PSS', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'rsa-pss',
      {
        modulusLength: 2048,
        hashAlgorithm: 'SHA-256',
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

  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);
});

// --- EC Key Generation Tests ---

test(SUITE, 'generateKeyPair EC P-256', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'ec',
      {
        namedCurve: 'P-256',
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

  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);

  const key = createPrivateKey(privateKey);
  expect(key.asymmetricKeyType).to.equal('ec');
});

test(SUITE, 'generateKeyPair EC P-384', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'ec',
      {
        namedCurve: 'P-384',
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

  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);
});

test(SUITE, 'generateKeyPair EC P-521', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'ec',
      {
        namedCurve: 'P-521',
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

  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);
});

test(SUITE, 'generateKeyPair EC keys work for signing', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'ec',
      {
        namedCurve: 'P-256',
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

  const testData = 'Test data for ECDSA signing';
  const signature = createSign('SHA256').update(testData).sign(privateKey);
  const isValid = createVerify('SHA256')
    .update(testData)
    .verify(publicKey, signature);

  expect(isValid).to.equal(true);
});

// --- Ed25519 Key Generation Tests ---

test(SUITE, 'generateKeyPair Ed25519 with PEM encoding', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'ed25519',
      {
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

  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);

  const key = createPrivateKey(privateKey);
  expect(key.asymmetricKeyType).to.equal('ed25519');
});

test(SUITE, 'generateKeyPair Ed25519 with DER encoding', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: ArrayBuffer;
    publicKey: ArrayBuffer;
  }>((resolve, reject) => {
    generateKeyPair(
      'ed25519',
      {
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      },
      (err, pubKey, privKey) => {
        if (err) reject(err);
        else
          resolve({
            privateKey: privKey as ArrayBuffer,
            publicKey: pubKey as ArrayBuffer,
          });
      },
    );
  });

  expect(privateKey instanceof ArrayBuffer).to.equal(true);
  expect(publicKey instanceof ArrayBuffer).to.equal(true);
});

// --- Ed448 Key Generation Tests ---

test(SUITE, 'generateKeyPair Ed448 with PEM encoding', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'ed448',
      {
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

  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);

  const key = createPrivateKey(privateKey);
  expect(key.asymmetricKeyType).to.equal('ed448');
});

// --- X25519 Key Generation Tests ---

test(SUITE, 'generateKeyPair X25519 with PEM encoding', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'x25519',
      {
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

  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);

  const key = createPrivateKey(privateKey);
  expect(key.asymmetricKeyType).to.equal('x25519');
});

// --- X448 Key Generation Tests ---

test(SUITE, 'generateKeyPair X448 with PEM encoding', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'x448',
      {
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

  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);

  const key = createPrivateKey(privateKey);
  expect(key.asymmetricKeyType).to.equal('x448');
});

// --- generateKeyPairSync Tests ---

test(SUITE, 'generateKeyPairSync Ed25519', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  expect(typeof privateKey).to.equal('string');
  expect(typeof publicKey).to.equal('string');
  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);
});

test(SUITE, 'generateKeyPairSync X25519', () => {
  const { privateKey, publicKey } = generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  expect(typeof privateKey).to.equal('string');
  expect(typeof publicKey).to.equal('string');
});

test(SUITE, 'generateKeyPairSync Ed448', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed448', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  expect(typeof privateKey).to.equal('string');
  expect(typeof publicKey).to.equal('string');
});

test(SUITE, 'generateKeyPairSync X448', () => {
  const { privateKey, publicKey } = generateKeyPairSync('x448', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  expect(typeof privateKey).to.equal('string');
  expect(typeof publicKey).to.equal('string');
});

// --- Error Cases ---

test(
  SUITE,
  'generateKeyPair with invalid type calls callback with error',
  async () => {
    await assertThrowsAsync(async () => {
      await Promise.race([
        new Promise<void>((resolve, reject) => {
          generateKeyPair(
            'invalid-type' as 'rsa',
            {
              modulusLength: 2048,
              publicKeyEncoding: { type: 'spki', format: 'pem' },
              privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
            },
            err => {
              if (err) reject(err);
              else resolve();
            },
          );
        }),
        new Promise((_, reject) =>
          setTimeout(
            () => reject(new Error('Timeout: callback never called')),
            1000,
          ),
        ),
      ]);
    }, '');
  },
);

// --- generateKeyPairSync RSA Tests ---

test(SUITE, 'generateKeyPairSync RSA 2048-bit with PEM encoding', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  expect(typeof privateKey).to.equal('string');
  expect(typeof publicKey).to.equal('string');
  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);
});

test(SUITE, 'generateKeyPairSync RSA with DER encoding', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });

  expect(privateKey instanceof ArrayBuffer).to.equal(true);
  expect(publicKey instanceof ArrayBuffer).to.equal(true);
  expect((privateKey as ArrayBuffer).byteLength).to.be.greaterThan(0);
  expect((publicKey as ArrayBuffer).byteLength).to.be.greaterThan(0);
});

test(SUITE, 'generateKeyPairSync RSA keys work for signing', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const testData = 'Test data for sync RSA signing';
  const signature = createSign('SHA256')
    .update(testData)
    .sign(privateKey as string);
  const isValid = createVerify('SHA256')
    .update(testData)
    .verify(publicKey as string, signature);

  expect(isValid).to.equal(true);
});

test(SUITE, 'generateKeyPairSync RSA-PSS', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa-pss', {
    modulusLength: 2048,
    hashAlgorithm: 'SHA-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  expect(typeof privateKey).to.equal('string');
  expect(typeof publicKey).to.equal('string');
  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);
});

// --- generateKeyPairSync EC Tests ---

test(SUITE, 'generateKeyPairSync EC P-256', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  expect(typeof privateKey).to.equal('string');
  expect(typeof publicKey).to.equal('string');
  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);

  const key = createPrivateKey(privateKey as string);
  expect(key.asymmetricKeyType).to.equal('ec');
});

test(SUITE, 'generateKeyPairSync EC P-384', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-384',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  expect(typeof privateKey).to.equal('string');
  expect(typeof publicKey).to.equal('string');
  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);
});

test(SUITE, 'generateKeyPairSync EC P-521', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-521',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  expect(typeof privateKey).to.equal('string');
  expect(typeof publicKey).to.equal('string');
  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);
});

test(SUITE, 'generateKeyPairSync EC keys work for signing', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const testData = 'Test data for sync ECDSA signing';
  const signature = createSign('SHA256')
    .update(testData)
    .sign(privateKey as string);
  const isValid = createVerify('SHA256')
    .update(testData)
    .verify(publicKey as string, signature);

  expect(isValid).to.equal(true);
});

test(SUITE, 'generateKeyPairSync EC with DER encoding', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });

  expect(privateKey instanceof ArrayBuffer).to.equal(true);
  expect(publicKey instanceof ArrayBuffer).to.equal(true);
  expect((privateKey as ArrayBuffer).byteLength).to.be.greaterThan(0);
  expect((publicKey as ArrayBuffer).byteLength).to.be.greaterThan(0);
});

// --- DSA Key Generation Tests ---

test(SUITE, 'generateKeyPair DSA 2048-bit with PEM encoding', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'dsa',
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

  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);
});

test(SUITE, 'generateKeyPair DSA with custom divisorLength', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'dsa',
      {
        modulusLength: 2048,
        divisorLength: 256,
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

  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);
});

test(SUITE, 'generateKeyPair DSA with DER encoding', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: ArrayBuffer;
    publicKey: ArrayBuffer;
  }>((resolve, reject) => {
    generateKeyPair(
      'dsa',
      {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      },
      (err, pubKey, privKey) => {
        if (err) reject(err);
        else
          resolve({
            privateKey: privKey as ArrayBuffer,
            publicKey: pubKey as ArrayBuffer,
          });
      },
    );
  });

  expect(privateKey instanceof ArrayBuffer).to.equal(true);
  expect(publicKey instanceof ArrayBuffer).to.equal(true);
  expect(privateKey.byteLength).to.be.greaterThan(0);
  expect(publicKey.byteLength).to.be.greaterThan(0);
});

test(SUITE, 'generateKeyPairSync DSA 2048-bit', () => {
  const { privateKey, publicKey } = generateKeyPairSync('dsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  expect(typeof privateKey).to.equal('string');
  expect(typeof publicKey).to.equal('string');
  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);
});

test(SUITE, 'generateKeyPairSync DSA keys work for signing', () => {
  const { privateKey, publicKey } = generateKeyPairSync('dsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const testData = 'Test data for DSA signing';
  const signature = createSign('SHA256')
    .update(testData)
    .sign(privateKey as string);
  const isValid = createVerify('SHA256')
    .update(testData)
    .verify(publicKey as string, signature);

  expect(isValid).to.equal(true);
});

// --- DH Key Generation Tests ---

test(SUITE, 'generateKeyPair DH with named group modp14', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'dh',
      {
        groupName: 'modp14',
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

  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);
});

test(SUITE, 'generateKeyPair DH with primeLength', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'dh',
      {
        primeLength: 512,
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

  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);
});

test(SUITE, 'generateKeyPairSync DH with named group', () => {
  const { privateKey, publicKey } = generateKeyPairSync('dh', {
    groupName: 'modp14',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  expect(typeof privateKey).to.equal('string');
  expect(typeof publicKey).to.equal('string');
  expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);
});

test(SUITE, 'generateKeyPairSync DH with DER encoding', () => {
  const { privateKey, publicKey } = generateKeyPairSync('dh', {
    groupName: 'modp14',
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });

  expect(privateKey instanceof ArrayBuffer).to.equal(true);
  expect(publicKey instanceof ArrayBuffer).to.equal(true);
  expect((privateKey as ArrayBuffer).byteLength).to.be.greaterThan(0);
  expect((publicKey as ArrayBuffer).byteLength).to.be.greaterThan(0);
});
