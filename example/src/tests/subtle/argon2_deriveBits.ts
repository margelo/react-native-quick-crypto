import { expect } from 'chai';
import { subtle, Buffer } from 'react-native-quick-crypto';
import { test } from '../util';

const SUITE = 'subtle.deriveBits';

// RFC 9106 test vectors — same password, nonce, secret, and associated data
// across all three variants, with variant-specific expected outputs.
const password = Buffer.alloc(32, 0x01);
const params = {
  memory: 32,
  passes: 3,
  parallelism: 4,
  nonce: Buffer.alloc(16, 0x02),
  secretValue: Buffer.alloc(8, 0x03),
  associatedData: Buffer.alloc(12, 0x04),
};

const vectors: {
  algorithm: 'Argon2d' | 'Argon2i' | 'Argon2id';
  tag: string;
}[] = [
  {
    algorithm: 'Argon2d',
    tag: '512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb',
  },
  {
    algorithm: 'Argon2i',
    tag: 'c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8',
  },
  {
    algorithm: 'Argon2id',
    tag: '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
  },
];

// --- deriveBits with RFC 9106 test vectors ---

for (const { algorithm, tag } of vectors) {
  test(SUITE, `deriveBits: ${algorithm} RFC 9106 test vector`, async () => {
    const key = await subtle.importKey(
      'raw-secret',
      password,
      algorithm,
      false,
      ['deriveBits'],
    );

    const result = await subtle.deriveBits(
      { name: algorithm, ...params },
      key,
      256,
    );

    expect(result).to.be.instanceOf(ArrayBuffer);
    expect(result.byteLength).to.equal(32);
    expect(Buffer.from(result).toString('hex')).to.equal(tag);
  });
}

// --- deriveKey with RFC 9106 test vectors ---

for (const { algorithm, tag } of vectors) {
  test(SUITE, `deriveKey: ${algorithm} RFC 9106 → HMAC key`, async () => {
    const key = await subtle.importKey(
      'raw-secret',
      password,
      algorithm,
      false,
      ['deriveKey'],
    );

    const hmacKey = await subtle.deriveKey(
      { name: algorithm, ...params },
      key,
      { name: 'HMAC', length: 256, hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    );

    expect(hmacKey.type).to.equal('secret');
    expect(hmacKey.algorithm.name).to.equal('HMAC');

    const exported = await subtle.exportKey('raw', hmacKey);
    expect(Buffer.from(exported as ArrayBuffer).toString('hex')).to.equal(tag);
  });
}

// --- importKey validation ---

test(SUITE, 'importKey: Argon2id key is not extractable', async () => {
  const key = await subtle.importKey(
    'raw-secret',
    password,
    'Argon2id',
    false,
    ['deriveBits'],
  );

  expect(key.type).to.equal('secret');
  expect(key.algorithm.name).to.equal('Argon2id');
  expect(key.extractable).to.equal(false);
  expect(key.usages).to.include('deriveBits');
});

test(SUITE, 'importKey: Argon2id rejects extractable=true', async () => {
  try {
    await subtle.importKey('raw-secret', password, 'Argon2id', true, [
      'deriveBits',
    ]);
    expect.fail('should have thrown');
  } catch (e) {
    expect((e as Error).message).to.include('not extractable');
  }
});
