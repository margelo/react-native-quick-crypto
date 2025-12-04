import { test } from '../util';
import { expect } from 'chai';
import { subtle, getRandomValues } from 'react-native-quick-crypto';
import { CryptoKey } from 'react-native-quick-crypto';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const subtleAny = subtle as any;

const SUITE = 'subtle.wrapKey/unwrapKey';

// Test 1: Wrap/unwrap AES key with AES-KW
test(SUITE, 'wrap/unwrap AES-256 with AES-KW', async () => {
  const keyToWrap = await subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  const wrappingKey = await subtle.generateKey(
    { name: 'AES-KW', length: 256 },
    true,
    ['wrapKey', 'unwrapKey'],
  );

  const wrapped = await subtleAny.wrapKey(
    'raw',
    keyToWrap as CryptoKey,
    wrappingKey as CryptoKey,
    { name: 'AES-KW' },
  );

  const unwrapped = await subtleAny.unwrapKey(
    'raw',
    wrapped,
    wrappingKey as CryptoKey,
    { name: 'AES-KW' },
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  // Verify keys are functionally identical
  const plaintext = getRandomValues(new Uint8Array(32));
  const iv = getRandomValues(new Uint8Array(12));

  const ct1 = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    keyToWrap as CryptoKey,
    plaintext,
  );

  const pt2 = await subtle.decrypt(
    { name: 'AES-GCM', iv },
    unwrapped as CryptoKey,
    ct1,
  );

  expect(Buffer.from(pt2).toString('hex')).to.equal(
    Buffer.from(plaintext).toString('hex'),
  );
});

// Test 2: Wrap with AES-GCM
test(SUITE, 'wrap/unwrap with AES-GCM', async () => {
  const keyToWrap = await subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign', 'verify'],
  );

  const wrappingKey = await subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['wrapKey', 'unwrapKey'],
  );

  const iv = getRandomValues(new Uint8Array(12));

  const wrapped = await subtleAny.wrapKey(
    'raw',
    keyToWrap as CryptoKey,
    wrappingKey as CryptoKey,
    { name: 'AES-GCM', iv },
  );

  const unwrapped = await subtleAny.unwrapKey(
    'raw',
    wrapped,
    wrappingKey as CryptoKey,
    { name: 'AES-GCM', iv },
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  );

  // Verify functionality
  const data = new Uint8Array([1, 2, 3, 4]);
  const sig1 = await subtle.sign(
    { name: 'HMAC' },
    keyToWrap as CryptoKey,
    data,
  );
  const sig2 = await subtle.sign(
    { name: 'HMAC' },
    unwrapped as CryptoKey,
    data,
  );

  expect(Buffer.from(sig1).toString('hex')).to.equal(
    Buffer.from(sig2).toString('hex'),
  );
});

// Test 3: Wrap/unwrap JWK format
test(SUITE, 'wrap/unwrap JWK format', async () => {
  const keyToWrap = await subtle.generateKey(
    { name: 'AES-CBC', length: 128 },
    true,
    ['encrypt', 'decrypt'],
  );

  const wrappingKey = await subtle.generateKey(
    { name: 'AES-KW', length: 256 },
    true,
    ['wrapKey', 'unwrapKey'],
  );

  const wrapped = await subtleAny.wrapKey(
    'jwk',
    keyToWrap as CryptoKey,
    wrappingKey as CryptoKey,
    { name: 'AES-KW' },
  );

  const unwrapped = await subtleAny.unwrapKey(
    'jwk',
    wrapped,
    wrappingKey as CryptoKey,
    { name: 'AES-KW' },
    { name: 'AES-CBC' },
    true,
    ['encrypt', 'decrypt'],
  );

  const exported1 = await subtle.exportKey('raw', keyToWrap as CryptoKey);
  const exported2 = await subtle.exportKey('raw', unwrapped as CryptoKey);

  expect(Buffer.from(exported1 as ArrayBuffer).toString('hex')).to.equal(
    Buffer.from(exported2 as ArrayBuffer).toString('hex'),
  );
});
