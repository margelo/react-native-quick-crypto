import { test } from '../util';
import { expect } from 'chai';
import { subtle, getRandomValues } from 'react-native-quick-crypto';
import { CryptoKey } from 'react-native-quick-crypto';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const subtleAny = subtle as any;

const SUITE = 'subtle.sign/verify HMAC';

// Test 1: Basic HMAC sign/verify with SHA-256
test(SUITE, 'HMAC-SHA256 sign and verify', async () => {
  const key = await subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign', 'verify'],
  );

  const data = new Uint8Array([1, 2, 3, 4, 5]);

  const signature = await subtleAny.sign(
    { name: 'HMAC' },
    key as CryptoKey,
    data,
  );

  expect(signature).to.be.instanceOf(ArrayBuffer);
  expect(signature.byteLength).to.equal(32); // SHA-256 = 32 bytes

  const valid = await subtleAny.verify(
    { name: 'HMAC' },
    key as CryptoKey,
    signature,
    data,
  );

  expect(valid).to.equal(true);
});

// Test 2: HMAC with different hash algorithms
test(SUITE, 'HMAC with SHA-384', async () => {
  const key = await subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-384' },
    false,
    ['sign', 'verify'],
  );

  const data = new Uint8Array([1, 2, 3, 4]);

  const signature = await subtleAny.sign(
    { name: 'HMAC' },
    key as CryptoKey,
    data,
  );

  expect(signature.byteLength).to.equal(48); // SHA-384 = 48 bytes

  const valid = await subtleAny.verify(
    { name: 'HMAC' },
    key as CryptoKey,
    signature,
    data,
  );

  expect(valid).to.equal(true);
});

// Test 3: HMAC with SHA-512
test(SUITE, 'HMAC with SHA-512', async () => {
  const key = await subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-512' },
    false,
    ['sign', 'verify'],
  );

  const data = new Uint8Array([1, 2, 3, 4]);

  const signature = await subtleAny.sign(
    { name: 'HMAC' },
    key as CryptoKey,
    data,
  );

  expect(signature.byteLength).to.equal(64); // SHA-512 = 64 bytes

  const valid = await subtleAny.verify(
    { name: 'HMAC' },
    key as CryptoKey,
    signature,
    data,
  );

  expect(valid).to.equal(true);
});

// Test 4: Verify with wrong signature
test(SUITE, 'HMAC verify fails with wrong signature', async () => {
  const key = await subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );

  const data = new Uint8Array([1, 2, 3, 4]);
  const wrongSignature = getRandomValues(new Uint8Array(32));

  const valid = await subtleAny.verify(
    { name: 'HMAC' },
    key as CryptoKey,
    wrongSignature,
    data,
  );

  expect(valid).to.equal(false);
});

// Test 5: Verify with wrong data
test(SUITE, 'HMAC verify fails with wrong data', async () => {
  const key = await subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );

  const data = new Uint8Array([1, 2, 3, 4]);
  const signature = await subtleAny.sign(
    { name: 'HMAC' },
    key as CryptoKey,
    data,
  );

  const wrongData = new Uint8Array([5, 6, 7, 8]);
  const valid = await subtleAny.verify(
    { name: 'HMAC' },
    key as CryptoKey,
    signature,
    wrongData,
  );

  expect(valid).to.equal(false);
});

// Test 6: Wrong key usage for sign
test(SUITE, 'HMAC sign fails without sign usage', async () => {
  const key = await subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'], // Only verify, not sign
  );

  const data = new Uint8Array([1, 2, 3, 4]);

  try {
    await subtleAny.sign({ name: 'HMAC' }, key as CryptoKey, data);
    expect.fail('Should have thrown');
  } catch (error) {
    expect((error as Error).message).to.include('sign usage');
  }
});

// Test 7: Wrong key usage for verify
test(SUITE, 'HMAC verify fails without verify usage', async () => {
  const key = await subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'], // Only sign, not verify
  );

  const data = new Uint8Array([1, 2, 3, 4]);
  const signature = getRandomValues(new Uint8Array(32));

  try {
    await subtleAny.verify({ name: 'HMAC' }, key as CryptoKey, signature, data);
    expect.fail('Should have thrown');
  } catch (error) {
    expect((error as Error).message).to.include('verify usage');
  }
});

// Test 8: Large data
test(SUITE, 'HMAC with large data', async () => {
  const key = await subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );

  const data = getRandomValues(new Uint8Array(10000));

  const signature = await subtleAny.sign(
    { name: 'HMAC' },
    key as CryptoKey,
    data,
  );

  const valid = await subtleAny.verify(
    { name: 'HMAC' },
    key as CryptoKey,
    signature,
    data,
  );

  expect(valid).to.equal(true);
});
