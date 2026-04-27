import crypto, { Buffer, hkdf, hkdfSync } from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';

const SUITE = 'hkdf';

// RFC 5869 Test Cases 1–7
// https://www.rfc-editor.org/rfc/rfc5869#appendix-A
//
// Cases 1–3 use SHA-256, cases 4–6 use SHA-1, case 7 is SHA-1 with empty
// salt and empty info (the "default salt = HashLen zero bytes" path).
const testVectors = [
  // A.1 — Test Case 1: Basic test case with SHA-256
  {
    ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    salt: '000102030405060708090a0b0c',
    info: 'f0f1f2f3f4f5f6f7f8f9',
    len: 42,
    okm: '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    algo: 'sha256',
  },
  // A.2 — Test Case 2: Test with SHA-256 and longer inputs/outputs
  {
    ikm: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f',
    salt: '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
    info: 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    len: 82,
    okm: 'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87',
    algo: 'sha256',
  },
  // A.3 — Test Case 3: SHA-256 with zero-length salt and zero-length info
  {
    ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    salt: '',
    info: '',
    len: 42,
    okm: '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
    algo: 'sha256',
  },
  // A.4 — Test Case 4: Basic test case with SHA-1
  {
    ikm: '0b0b0b0b0b0b0b0b0b0b0b',
    salt: '000102030405060708090a0b0c',
    info: 'f0f1f2f3f4f5f6f7f8f9',
    len: 42,
    okm: '085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896',
    algo: 'sha1',
  },
  // A.5 — Test Case 5: SHA-1 with longer inputs/outputs
  {
    ikm: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f',
    salt: '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
    info: 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    len: 82,
    okm: '0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4',
    algo: 'sha1',
  },
  // A.6 — Test Case 6: SHA-1 with zero-length salt and zero-length info
  {
    ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    salt: '',
    info: '',
    len: 42,
    okm: '0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918',
    algo: 'sha1',
  },
  // A.7 — Test Case 7: SHA-1, salt == NULL (treated as HashLen zeros), zero info
  {
    ikm: '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
    salt: '',
    info: '',
    len: 42,
    okm: '2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48',
    algo: 'sha1',
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

// RFC 5869 Test Case 4 via WebCrypto subtle (SHA-1 path) — exercises the
// hash-name normalization branch the Node-API tests don't reach.
test(SUITE, 'WebCrypto HKDF deriveBits SHA-1 (RFC 5869 Case 4)', async () => {
  const vec = testVectors[3]!; // case 4
  const ikm = Buffer.from(vec.ikm, 'hex');
  const salt = Buffer.from(vec.salt, 'hex');
  const info = Buffer.from(vec.info, 'hex');

  const key = await crypto.subtle.importKey(
    'raw',
    ikm,
    { name: 'HKDF' },
    false,
    ['deriveBits'],
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-1',
      salt,
      info,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any,
    key,
    vec.len * 8,
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

test(SUITE, 'hkdfSync: rejects unsupported digest (shake128)', () => {
  const ikm = Buffer.from('00', 'hex');
  // SHAKE is an extendable-output function, not a fixed-length hash, so it
  // is not a valid HKDF digest (HKDF builds on HMAC, which requires a
  // fixed-length hash). The validator surfaces this as a TypeError before
  // the call reaches OpenSSL.
  expect(() => {
    hkdfSync('shake128', ikm, Buffer.alloc(0), Buffer.alloc(0), 32);
  }).to.throw(TypeError, /Unsupported HKDF digest/);
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

// Phase 3.5 regression: WebCrypto §28.7.6 mandates HKDF keys be created
// with extractable=false. The previous implementation passed `extractable`
// through verbatim, allowing input keying material to round-trip via
// exportKey — defeating the deriveBits-only usage.
test(SUITE, 'HKDF importKey: rejects extractable=true', async () => {
  const ikm = Buffer.from('00'.repeat(16), 'hex');
  let threw: Error | undefined;
  try {
    await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, true, [
      'deriveBits',
    ]);
  } catch (e) {
    threw = e as Error;
  }
  expect(threw).to.not.equal(undefined);
  expect(threw!.message).to.match(/HKDF keys are not extractable/);
});

test(
  SUITE,
  'HKDF importKey: forces extractable=false even when false',
  async () => {
    const ikm = Buffer.from('00'.repeat(16), 'hex');
    const key = await crypto.subtle.importKey(
      'raw',
      ikm,
      { name: 'HKDF' },
      false,
      ['deriveBits'],
    );
    expect(key.extractable).to.equal(false);
  },
);

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
