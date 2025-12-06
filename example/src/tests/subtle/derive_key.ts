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
