import { test } from '../util';
import { expect } from 'chai';
import { subtle, getRandomValues } from 'react-native-quick-crypto';
import { CryptoKey } from 'react-native-quick-crypto';
import type { CryptoKeyPair } from 'react-native-quick-crypto';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const subtleAny = subtle as any;

const SUITE = 'subtle.deriveKey';

// Test 1: PBKDF2 deriveKey
test(SUITE, 'PBKDF2 deriveKey to AES-GCM', async () => {
  const password = new TextEncoder().encode('my-password');
  const salt = getRandomValues(new Uint8Array(16));

  const baseKey = await subtle.importKey(
    'raw',
    password,
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  );

  const derivedKey = await subtleAny.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    baseKey as CryptoKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  // Verify key can encrypt/decrypt
  const plaintext = new Uint8Array([1, 2, 3, 4]);
  const iv = getRandomValues(new Uint8Array(12));

  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    derivedKey as CryptoKey,
    plaintext,
  );

  const decrypted = await subtle.decrypt(
    { name: 'AES-GCM', iv },
    derivedKey as CryptoKey,
    ciphertext,
  );

  expect(Buffer.from(decrypted).toString('hex')).to.equal(
    Buffer.from(plaintext).toString('hex'),
  );
});

// Test 2: X25519 deriveKey
test(SUITE, 'X25519 deriveKey to AES-GCM', async () => {
  const aliceKeyPair = await subtle.generateKey({ name: 'X25519' }, false, [
    'deriveKey',
    'deriveBits',
  ]);

  const bobKeyPair = await subtle.generateKey({ name: 'X25519' }, false, [
    'deriveKey',
    'deriveBits',
  ]);

  const aliceDerivedKey = await subtleAny.deriveKey(
    {
      name: 'X25519',
      public: (bobKeyPair as CryptoKeyPair).publicKey,
    },
    (aliceKeyPair as CryptoKeyPair).privateKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  const bobDerivedKey = await subtleAny.deriveKey(
    {
      name: 'X25519',
      public: (aliceKeyPair as CryptoKeyPair).publicKey,
    },
    (bobKeyPair as CryptoKeyPair).privateKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  // Both should derive the same key
  const aliceRaw = await subtle.exportKey('raw', aliceDerivedKey as CryptoKey);
  const bobRaw = await subtle.exportKey('raw', bobDerivedKey as CryptoKey);

  expect(Buffer.from(aliceRaw as ArrayBuffer).toString('hex')).to.equal(
    Buffer.from(bobRaw as ArrayBuffer).toString('hex'),
  );
});

// Tests 3-N: ECDH deriveKey for all curves and AES key lengths
// P-384 and P-521 are regression tests for #946: shared secret > derived key
// length must be properly truncated (subarray().buffer returned full backing buffer)
const ecdhDeriveKeyTests: Array<{
  curve: 'P-256' | 'P-384' | 'P-521';
  aesLength: 128 | 256;
}> = [
  { curve: 'P-256', aesLength: 256 },
  { curve: 'P-384', aesLength: 256 },
  { curve: 'P-384', aesLength: 128 },
  { curve: 'P-521', aesLength: 256 },
  { curve: 'P-521', aesLength: 128 },
];

for (const { curve, aesLength } of ecdhDeriveKeyTests) {
  test(SUITE, `ECDH ${curve} deriveKey to AES-GCM-${aesLength}`, async () => {
    const aliceKeyPair = await subtle.generateKey(
      { name: 'ECDH', namedCurve: curve },
      false,
      ['deriveKey', 'deriveBits'],
    );

    const bobKeyPair = await subtle.generateKey(
      { name: 'ECDH', namedCurve: curve },
      false,
      ['deriveKey', 'deriveBits'],
    );

    const aliceDerivedKey = await subtleAny.deriveKey(
      {
        name: 'ECDH',
        public: (aliceKeyPair as CryptoKeyPair).publicKey,
      },
      (bobKeyPair as CryptoKeyPair).privateKey,
      { name: 'AES-GCM', length: aesLength },
      true,
      ['encrypt', 'decrypt'],
    );

    const bobDerivedKey = await subtleAny.deriveKey(
      {
        name: 'ECDH',
        public: (bobKeyPair as CryptoKeyPair).publicKey,
      },
      (aliceKeyPair as CryptoKeyPair).privateKey,
      { name: 'AES-GCM', length: aesLength },
      true,
      ['encrypt', 'decrypt'],
    );

    const aliceRaw = await subtle.exportKey(
      'raw',
      aliceDerivedKey as CryptoKey,
    );
    const bobRaw = await subtle.exportKey('raw', bobDerivedKey as CryptoKey);

    expect(Buffer.from(aliceRaw as ArrayBuffer).byteLength).to.equal(
      aesLength / 8,
    );
    expect(Buffer.from(aliceRaw as ArrayBuffer).toString('hex')).to.equal(
      Buffer.from(bobRaw as ArrayBuffer).toString('hex'),
    );

    // Verify encrypt/decrypt round-trip
    const plaintext = new Uint8Array([1, 2, 3, 4]);
    const iv = getRandomValues(new Uint8Array(12));

    const ciphertext = await subtle.encrypt(
      { name: 'AES-GCM', iv },
      aliceDerivedKey as CryptoKey,
      plaintext,
    );

    const decrypted = await subtle.decrypt(
      { name: 'AES-GCM', iv },
      bobDerivedKey as CryptoKey,
      ciphertext,
    );

    expect(Buffer.from(decrypted).toString('hex')).to.equal(
      Buffer.from(plaintext).toString('hex'),
    );
  });
}

// Test: ECDH P-384 deriveKey to AES-CBC-256
test(SUITE, 'ECDH P-384 deriveKey to AES-CBC-256', async () => {
  const alice = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-384' },
    false,
    ['deriveKey'],
  );
  const bob = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-384' },
    false,
    ['deriveKey'],
  );

  const aliceKey = await subtleAny.deriveKey(
    { name: 'ECDH', public: (bob as CryptoKeyPair).publicKey },
    (alice as CryptoKeyPair).privateKey,
    { name: 'AES-CBC', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  const bobKey = await subtleAny.deriveKey(
    { name: 'ECDH', public: (alice as CryptoKeyPair).publicKey },
    (bob as CryptoKeyPair).privateKey,
    { name: 'AES-CBC', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  const plaintext = new Uint8Array([5, 6, 7, 8]);
  const iv = getRandomValues(new Uint8Array(16));

  const ciphertext = await subtle.encrypt(
    { name: 'AES-CBC', iv },
    aliceKey as CryptoKey,
    plaintext,
  );

  const decrypted = await subtle.decrypt(
    { name: 'AES-CBC', iv },
    bobKey as CryptoKey,
    ciphertext,
  );

  expect(Buffer.from(decrypted).toString('hex')).to.equal(
    Buffer.from(plaintext).toString('hex'),
  );
});
