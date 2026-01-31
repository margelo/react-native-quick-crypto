/* eslint-disable @typescript-eslint/no-unused-expressions */
import { Buffer } from 'safe-buffer';
import { expect } from 'chai';
import { test } from '../util';

import crypto from 'react-native-quick-crypto';

const SUITE = 'scrypt';

// RFC 7914 Test Vectors
// https://tools.ietf.org/html/rfc7914#section-2
const kTests = [
  {
    password: '',
    salt: '',
    N: 16,
    r: 1,
    p: 1,
    keylen: 64,
    expected:
      '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906',
  },
  {
    password: 'password',
    salt: 'NaCl',
    N: 1024,
    r: 8,
    p: 16,
    keylen: 64,
    expected:
      'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640',
  },
  {
    password: 'pleaseletmein',
    salt: 'SodiumChloride',
    N: 16384,
    r: 8,
    p: 1,
    keylen: 64,
    expected:
      '7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887',
  },
];

kTests.forEach(({ password, salt, N, r, p, keylen, expected }, index) => {
  const description = `RFC 7914 Test Case ${index + 1}`;

  test(SUITE, `${description} (async)`, () => {
    crypto.scrypt(
      password,
      salt,
      keylen,
      { N, r, p, maxmem: 32 * 1024 * 1024 }, // 32MB - generous headroom for all test cases
      (err, derivedKey) => {
        expect(err).to.be.null;
        expect(derivedKey).not.to.be.undefined;
        expect(derivedKey!.toString('hex')).to.equal(expected);
      },
    );
  });

  test(SUITE, `${description} (sync)`, () => {
    const derivedKey = crypto.scryptSync(password, salt, keylen, {
      N,
      r,
      p,
      maxmem: 32 * 1024 * 1024, // 32MB - generous headroom for all test cases
    });
    expect(derivedKey).not.to.be.undefined;
    expect(derivedKey.toString('hex')).to.equal(expected);
  });
});

test(SUITE, 'should throw if no callback provided (async)', () => {
  expect(() => {
    crypto.scrypt('password', 'salt', 64);
  }).to.throw(/No callback provided/);
});

test(SUITE, 'should handle default options (async)', () => {
  // This just tests it doesn't crash and returns a buffer
  crypto.scrypt('password', 'salt', 32, (err, key) => {
    expect(err).to.be.null;
    expect(Buffer.isBuffer(key)).to.equal(true);
    expect(key!.length).to.equal(32);
  });
});

test(SUITE, 'should handle aliases cost/blockSize/parallelization', () => {
  // Same as Test Case 1 but with named aliases
  const t = kTests[0]!;
  const derivedKey = crypto.scryptSync(t.password, t.salt, t.keylen, {
    cost: t.N,
    blockSize: t.r,
    parallelization: t.p,
  });
  expect(derivedKey.toString('hex')).to.equal(t.expected);
});
