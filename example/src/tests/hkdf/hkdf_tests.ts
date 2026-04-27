import crypto, { Buffer, hkdf, hkdfSync } from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';

const SUITE = 'hkdf';

// RFC 5869 Test Case 1
const testVectors = [
  {
    ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', // 22 bytes
    salt: '000102030405060708090a0b0c', // 13 bytes
    info: 'f0f1f2f3f4f5f6f7f8f9', // 10 bytes
    len: 42,
    okm: '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    algo: 'sha256',
  },
];

for (let i = 0; i < testVectors.length; i++) {
  const vec = testVectors[i]!;

  test(SUITE, `HKDF Sync (RFC 5869 Case ${i + 1})`, () => {
    const ikm = Buffer.from(vec.ikm, 'hex');
    const salt = Buffer.from(vec.salt, 'hex');
    const info = Buffer.from(vec.info, 'hex');

    const key = hkdfSync(vec.algo, ikm, salt, info, vec.len);
    expect(key.toString('hex')).to.equal(vec.okm);
  });

  test(SUITE, `HKDF Async (RFC 5869 Case ${i + 1})`, async () => {
    const ikm = Buffer.from(vec.ikm, 'hex');
    const salt = Buffer.from(vec.salt, 'hex');
    const info = Buffer.from(vec.info, 'hex');

    return new Promise<void>((resolve, reject) => {
      hkdf(vec.algo, ikm, salt, info, vec.len, (err, key) => {
        try {
          expect(err).to.equal(null);
          expect(key?.toString('hex')).to.equal(vec.okm);
          resolve();
        } catch (e) {
          reject(e);
        }
      });
    });
  });
}

// WebCrypto Tests
test(SUITE, 'WebCrypto HKDF importKey and deriveBits', async () => {
  const vec = testVectors[0]!;
  const ikm = Buffer.from(vec.ikm, 'hex');
  const salt = Buffer.from(vec.salt, 'hex');
  const info = Buffer.from(vec.info, 'hex');

  const key = await crypto.subtle.importKey(
    'raw',
    ikm,
    { name: 'HKDF' },
    false,
    ['deriveKey', 'deriveBits'],
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt,
      info: info,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any,
    key,
    vec.len * 8, // bits
  );

  expect(Buffer.from(bits).toString('hex')).to.equal(vec.okm);
});

// --- TS-layer HKDF parameter validation regression (Phase 3.2) ---
//
// RFC 5869 §2.3 caps L (output keylen in bytes) at 255 * HashLen. Pre-fix,
// callers could request any keylen; the native side either silently
// truncated or — in the worst case — produced an error string only after
// the round-trip. We now reject too-large requests at the JS boundary.

test(SUITE, 'hkdfSync: rejects negative keylen', () => {
  const ikm = Buffer.from('00', 'hex');
  expect(() => {
    hkdfSync('sha256', ikm, Buffer.alloc(0), Buffer.alloc(0), -1);
  }).to.throw(TypeError, /Bad key length/);
});

test(SUITE, 'hkdfSync: rejects keylen > 255 * HashLen for sha256', () => {
  const ikm = Buffer.from('00', 'hex');
  expect(() => {
    // 255 * 32 = 8160 bytes, so 8161 must be rejected.
    hkdfSync('sha256', ikm, Buffer.alloc(0), Buffer.alloc(0), 8161);
  }).to.throw(RangeError, /exceeds RFC 5869 ceiling/);
});

test(SUITE, 'hkdfSync: rejects keylen > 255 * HashLen for sha1', () => {
  const ikm = Buffer.from('00', 'hex');
  expect(() => {
    // 255 * 20 = 5100 bytes for sha1.
    hkdfSync('sha1', ikm, Buffer.alloc(0), Buffer.alloc(0), 5101);
  }).to.throw(RangeError, /exceeds RFC 5869 ceiling/);
});

test(SUITE, 'hkdfSync: accepts keylen at the RFC 5869 ceiling', () => {
  const ikm = Buffer.from('00', 'hex');
  // Exactly 255 * 32 = 8160 must succeed.
  expect(() => {
    hkdfSync('sha256', ikm, Buffer.alloc(0), Buffer.alloc(0), 8160);
  }).to.not.throw();
});

test(SUITE, 'hkdf: surfaces ceiling errors via callback', async () => {
  const ikm = Buffer.from('00', 'hex');
  await new Promise<void>((resolve, reject) => {
    hkdf('sha256', ikm, Buffer.alloc(0), Buffer.alloc(0), 9000, err => {
      try {
        expect(err).to.be.instanceOf(RangeError);
        expect(err!.message).to.match(/exceeds RFC 5869 ceiling/);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
});

test(SUITE, 'WebCrypto HKDF deriveKey (AES-GCM)', async () => {
  const vec = testVectors[0]!;
  const ikm = Buffer.from(vec.ikm, 'hex');
  const salt = Buffer.from(vec.salt, 'hex');
  const info = Buffer.from(vec.info, 'hex');

  const baseKey = await crypto.subtle.importKey(
    'raw',
    ikm,
    { name: 'HKDF' },
    false,
    ['deriveKey'],
  );

  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt,
      info: info,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any,
    baseKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  expect(derivedKey.algorithm.name).to.equal('AES-GCM');
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  expect((derivedKey.algorithm as any).length).to.equal(256);
  expect(derivedKey.usages).to.deep.equal(['encrypt', 'decrypt']);

  // Check key value matches OKM (truncated to 256 bits = 32 bytes)
  const rawDerived = (await crypto.subtle.exportKey(
    'raw',
    derivedKey,
  )) as ArrayBuffer;
  const expected = vec.okm.slice(0, 64); // 32 bytes * 2 hex chars
  expect(Buffer.from(rawDerived).toString('hex')).to.equal(expected);
});
