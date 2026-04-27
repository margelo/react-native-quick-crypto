/**
 * Tests are based on Node.js tests
 * https://github.com/nodejs/node/blob/master/test/parallel/test-crypto-hash.js
 */

import {
  Buffer,
  createHash,
  hash,
  getHashes,
  type Encoding,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';

const SUITE = 'hash';

test(SUITE, 'createHash with valid algorithm', () => {
  expect(() => {
    createHash('sha256');
  }).to.not.throw();
});

test(SUITE, 'createHash with invalid algorithm', () => {
  expect(() => {
    createHash('sha123');
  }).to.throw(/Unknown hash algorithm: sha123/);
});

test(SUITE, 'createHash with null algorithm', () => {
  expect(() => {
    // @ts-expect-error bad algorithm
    createHash(null);
  }).to.throw(/Algorithm must be a non-empty string/);
});

test(SUITE, 'check openssl version', () => {
  expect(() => {
    // Create a hash to trigger OpenSSL initialization
    const hash = createHash('sha256');

    // Get OpenSSL version directly from the hash object
    const version = hash.getOpenSSLVersion();
    console.log('OpenSSL Version:', version);
  }).to.not.throw();
});

test(SUITE, 'KECCAK-256 using createHash with provider-aware API', () => {
  // Test with a simple string
  const result1 = createHash('KECCAK-256').update('test').digest();
  expect(result1.toString('hex')).to.equal(
    '9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658',
  );

  // Test with empty string
  const result2 = createHash('KECCAK-256').update('').digest();
  expect(result2.toString('hex')).to.equal(
    'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
  );

  // Test with Buffer
  const result3 = createHash('KECCAK-256')
    .update(Buffer.from('hello world'))
    .digest();
  expect(result3.toString('hex')).to.equal(
    '47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad',
  );

  // Verify the result is 32 bytes (256 bits)
  expect(result1.length).to.equal(32);
  expect(result2.length).to.equal(32);
  expect(result3.length).to.equal(32);

  // Test that it's different from SHA3-256 (they should be different)
  const sha3Hash = createHash('SHA3-256').update('test').digest();
  expect(result1.toString('hex')).to.not.equal(sha3Hash.toString('hex'));
});

// test hashing
const a0 = createHash('md5').update('Test123').digest('latin1');
const a1 = createHash('sha1').update('Test123').digest('hex');
const a2 = createHash('sha256').update('Test123').digest('base64');
const a3 = createHash('sha512').update('Test123').digest(); // buffer
const a4 = createHash('sha1').update('Test123').digest('buffer');

test(SUITE, 'non stream - digest with latin1 argument', () => {
  expect(a0).to.deep.equal(
    'h\u00ea\u00cb\u0097\u00d8o\fF!\u00fa+\u000e\u0017\u00ca\u00bd\u008c',
  );
});
test(SUITE, 'non stream - digest with hex argument', () => {
  expect(a1).to.deep.equal('8308651804facb7b9af8ffc53a33a22d6a1c8ac2');
});
test(SUITE, 'non stream - digest with base64 argument', () => {
  expect(a2).to.deep.equal('2bX1jws4GYKTlxhloUB09Z66PoJZW+y+hq5R8dnx9l4=');
});
test(SUITE, 'non stream - digest with buffer argument', () => {
  expect(a4).to.deep.equal(
    Buffer.from('8308651804facb7b9af8ffc53a33a22d6a1c8ac2', 'hex'),
  );
});
test(SUITE, 'non stream - digest without argument defaults to buffer', () => {
  expect(a3).to.deep.equal(
    Buffer.from(
      "\u00c1(4\u00f1\u0003\u001fd\u0097!O'\u00d4C/&Qz\u00d4" +
        '\u0094\u0015l\u00b8\u008dQ+\u00db\u001d\u00c4\u00b5}\u00b2' +
        '\u00d6\u0092\u00a3\u00df\u00a2i\u00a1\u009b\n\n*\u000f' +
        '\u00d7\u00d6\u00a2\u00a8\u0085\u00e3<\u0083\u009c\u0093' +
        "\u00c2\u0006\u00da0\u00a1\u00879(G\u00ed'",
      'latin1',
    ),
  );
});

test(SUITE, 'non stream - multiple updates to same hash', () => {
  const h1 = createHash('sha1').update('Test').update('123').digest('hex');
  expect(h1).to.deep.equal(a1);
});

// stream interface
let a5 = createHash('sha512');
a5.end('Test123');
a5 = a5.read();
let a6 = createHash('sha512');
a6.write('Te');
a6.write('st');
a6.write('123');
a6.end();
a6 = a6.read();
let a7 = createHash('sha512');
a7.end();
a7 = a7.read();
let a8 = createHash('sha512');
a8.write('');
a8.end();
a8 = a8.read();

test(SUITE, 'stream - should produce the same output as non-stream', () => {
  expect(a5).to.deep.equal(a3);
  expect(a6).to.deep.equal(a3);
});
test(SUITE, 'stream - empty', () => {
  expect(a7).to.deep.equal(a8);
  expect(a7).not.to.deep.equal(undefined);
  expect(a8).not.to.deep.equal(undefined);
});

test(SUITE, 'copy - should create identical hash state', () => {
  const hash1 = createHash('sha256').update('Test123');
  const hash2 = hash1.copy();
  expect(hash1.digest('hex')).to.deep.equal(hash2.digest('hex'));
});

test(SUITE, 'copy - calculate a rolling hash', () => {
  const hash = createHash('sha256');
  hash.update('one');
  expect(hash.copy().digest('hex')).to.deep.equal(
    '7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed',
  );
  hash.update('two');
  expect(hash.copy().digest('hex')).to.deep.equal(
    '25b6746d5172ed6352966a013d93ac846e1110d5a25e8f183b5931f4688842a1',
  );
  hash.update('three');
  expect(hash.copy().digest('hex')).to.deep.equal(
    '4592092e1061c7ea85af2aed194621cc17a2762bae33a79bf8ce33fd0168b801',
  );
});

test(SUITE, 'getHashes - should return array of supported algorithms', () => {
  const algorithms = getHashes();
  const expectedAlgorithms = [
    'BLAKE2B-512',
    'BLAKE2S-256',
    'KECCAK-224',
    'KECCAK-256',
    'KECCAK-384',
    'KECCAK-512',
    'KECCAK-KMAC-128',
    'KECCAK-KMAC-256',
    'MD5',
    'MD5-SHA1',
    'NULL',
    'RIPEMD-160',
    'SHA1',
    'SHA2-224',
    'SHA2-256',
    'SHA2-256/192',
    'SHA2-384',
    'SHA2-512',
    'SHA2-512/224',
    'SHA2-512/256',
    'SHA3-224',
    'SHA3-256',
    'SHA3-384',
    'SHA3-512',
    'SHAKE-128',
    'SHAKE-256',
    'SM3',
  ];
  expect(algorithms).to.be.an('array');
  expect(algorithms.sort()).to.deep.equal(expectedAlgorithms.sort());
});

// errors
test(SUITE, 'digest - segfault', () => {
  const hash = createHash('sha256');
  expect(() => {
    hash.digest({
      toString: () => {
        throw new Error('segfault');
      },
    } as unknown as Encoding);
  }).to.throw();
});
test(SUITE, 'update - calling update without argument', () => {
  const hash = createHash('sha256');
  expect(() => {
    // @ts-expect-error calling update without argument
    hash.update();
  }).to.throw(/Invalid argument type/);
});
test(SUITE, 'digest - calling update after digest', () => {
  const hash = createHash('sha256');
  hash.digest();
  expect(() => hash.update('test')).to.throw(/Failed to update/);
});

// outputLength option
test(SUITE, 'output length = 0', () => {
  const hash = createHash('SHAKE-256', { outputLength: 0 });
  expect(hash.digest('hex')).to.deep.equal('');
});
test(SUITE, 'output length = 5', () => {
  expect(
    createHash('shake128', { outputLength: 5 }).digest('hex'),
  ).to.deep.equal('7f9c2ba4e8');
});
test(SUITE, 'output length with copy', () => {
  const hash = createHash('shake128', { outputLength: 5 });
  const copy = hash.copy({ outputLength: 0 });
  expect(copy.digest('hex')).to.deep.equal('');
  expect(hash.digest('hex')).to.deep.equal('7f9c2ba4e8');
});
test(SUITE, 'large output length', () => {
  const largeHash = createHash('shake128', { outputLength: 128 }).digest('hex');
  expect(largeHash.length).to.equal(2 * 128);
  expect(largeHash.slice(0, 32)).to.deep.equal(
    '7f9c2ba4e88f827d616045507605853e',
  );
  expect(largeHash.slice(2 * 128 - 32, 2 * 128)).to.deep.equal(
    'df9a04302e10c8bc1cbf1a0b3a5120ea',
  );
});
test(SUITE, 'super long hash', () => {
  const superLongHash = createHash('shake256', {
    outputLength: 1024 * 1024,
  })
    .update('The message is shorter than the hash!')
    .digest('hex');
  expect(superLongHash.length).to.equal(2 * 1024 * 1024);
  expect(superLongHash.slice(0, 32)).to.deep.equal(
    'a2a28dbc49cfd6e5d6ceea3d03e77748',
  );
  expect(
    superLongHash.slice(2 * 1024 * 1024 - 32, 2 * 1024 * 1024),
  ).to.deep.equal('193414035ddba77bf7bba97981e656ec');
});
test(SUITE, 'unreasonable output length', () => {
  expect(() => {
    createHash('shake128', { outputLength: 1024 * 1024 * 1024 }).digest('hex');
  }).to.throw(
    /Output length 1073741824 exceeds maximum allowed size of 16777216/,
  );
});
test(SUITE, 'createHash with negative outputLength', () => {
  expect(() => {
    createHash('shake128', { outputLength: -1 });
  }).to.throw(/Output length must be a non-negative number/);
});
test(SUITE, 'createHash with null outputLength', () => {
  expect(() => {
    // @ts-expect-error bad outputLength
    createHash('shake128', { outputLength: null });
  }).to.throw(/Output length must be a number/);
});

// crypto.hash() oneshot function tests
test(SUITE, 'hash() oneshot - sha256 hex', () => {
  const result = hash('sha256', 'Test123', 'hex');
  const expected = createHash('sha256').update('Test123').digest('hex');
  expect(result).to.equal(expected);
});

test(SUITE, 'hash() oneshot - sha256 base64', () => {
  const result = hash('sha256', 'Test123', 'base64');
  const expected = createHash('sha256').update('Test123').digest('base64');
  expect(result).to.equal(expected);
});

test(SUITE, 'hash() oneshot - returns Buffer without encoding', () => {
  const result = hash('sha256', 'Test123');
  expect(Buffer.isBuffer(result)).to.equal(true);
  expect(typeof result).to.not.equal('string');
});

test(SUITE, 'hash() oneshot - sha512', () => {
  const result = hash('sha512', 'hello world', 'hex');
  const expected = createHash('sha512').update('hello world').digest('hex');
  expect(result).to.equal(expected);
});

test(SUITE, 'hash() oneshot - md5', () => {
  const result = hash('md5', 'Test123', 'hex');
  expect(result).to.equal('68eacb97d86f0c4621fa2b0e17cabd8c');
});

test(SUITE, 'hash() oneshot - Buffer input', () => {
  const data = Buffer.from('hello');
  const result = hash('sha256', data, 'hex');
  const expected = createHash('sha256').update(data).digest('hex');
  expect(result).to.equal(expected);
});

// Phase 3.6 regression: synchronous failures inside `_transform` and
// `_flush` must surface as stream 'error' events rather than throwing
// out of the Transform plumbing — which can leave the stream in a
// half-written state and crash the host pipeline. Drive each path
// through the public stream API (write/end) and assert on 'error'.

test(SUITE, 'Hash: _transform error surfaces as "error" event', async () => {
  const h = createHash('sha256');
  h.digest(); // finalize the native context — next update() throws

  const error = await new Promise<Error>(resolve => {
    h.once('error', resolve);
    h.write('after digest');
  });
  expect(error).to.be.instanceOf(Error);
});

test(SUITE, 'Hash: _flush error surfaces as "error" event', async () => {
  const h = createHash('sha256');
  h.digest(); // first digest — second call (from _flush) throws

  const error = await new Promise<Error>(resolve => {
    h.once('error', resolve);
    h.end();
  });
  expect(error).to.be.instanceOf(Error);
});

// --- Phase 4.1: NIST FIPS 180-4 / FIPS 202 / FIPS 198-1 KATs ---
//
// Each SHA family has a published two-byte input ("abc") test vector and
// an empty-string vector. These vectors are produced by NIST's CSRC group
// and live in:
//   FIPS 180-4 Appendix C (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512,
//                         SHA-512/224, SHA-512/256)
//   https://csrc.nist.gov/CSRC/media/Publications/fips/180/4/final/documents/fips180-4.pdf
//   FIPS 202 §B.1 / NIST SP 800-185 (SHA-3, SHAKE)
//   https://csrc.nist.gov/CSRC/media/Publications/fips/202/final/documents/fips202.pdf
// Each test pins both the empty-string and "abc" outputs against the
// FIPS-published values. A wrong byte in our build (e.g. SHA-512/224 not
// using the SHA-512/t initial values, SHA-3 padding errors, MD5 byte
// ordering bugs) gets caught here.

const SHA_KATS = [
  // FIPS 180-4 §A.1 / §B.1
  {
    algo: 'sha1',
    empty: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
    abc: 'a9993e364706816aba3e25717850c26c9cd0d89d',
  },
  {
    algo: 'sha224',
    empty: 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f',
    abc: '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7',
  },
  {
    algo: 'sha256',
    empty: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    abc: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  },
  {
    algo: 'sha384',
    empty:
      '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
    abc: 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
  },
  {
    algo: 'sha512',
    empty:
      'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
    abc: 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
  },
  // FIPS 180-4 §A.4 / §B.4 — SHA-512/t variants. Empty-string values come
  // from `openssl dgst -sha512-224|-sha512-256` which match the FIPS 180-4
  // SHA-512/t derivation (different IV than SHA-512). The "abc" values
  // are the FIPS 180-4 published test vectors for those variants.
  {
    algo: 'sha512-224',
    empty: '6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4',
    abc: '4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa',
  },
  {
    algo: 'sha512-256',
    empty: 'c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a',
    abc: '53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23',
  },
  // FIPS 202 §B.1 — SHA-3 family
  {
    algo: 'sha3-224',
    empty: '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7',
    abc: 'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf',
  },
  {
    algo: 'sha3-256',
    empty: 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
    abc: '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
  },
  {
    algo: 'sha3-384',
    empty:
      '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004',
    abc: 'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25',
  },
  {
    algo: 'sha3-512',
    empty:
      'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
    abc: 'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0',
  },
];

for (const kat of SHA_KATS) {
  test(SUITE, `NIST KAT ${kat.algo} empty string`, () => {
    const got = createHash(kat.algo).update('').digest('hex');
    expect(got).to.equal(kat.empty);
  });

  test(SUITE, `NIST KAT ${kat.algo} "abc"`, () => {
    const got = createHash(kat.algo).update('abc').digest('hex');
    expect(got).to.equal(kat.abc);
  });

  test(SUITE, `NIST KAT ${kat.algo} via hash() one-shot ("abc")`, () => {
    const got = hash(kat.algo, 'abc', 'hex');
    expect(got).to.equal(kat.abc);
  });
}

// FIPS 180-4 §B.3 / §B.5 — the canonical 1,000,000 byte 'a' test vector
// for SHA-256 and SHA-512. We don't assert the value for every algorithm
// (the file would balloon) — these two pin the most-used digests against
// the long-input chunking path.
test(SUITE, 'NIST FIPS 180-4 §B.3 — SHA-256 of 1,000,000 "a"', () => {
  const buf = Buffer.alloc(1_000_000, 0x61); // 'a'
  expect(createHash('sha256').update(buf).digest('hex')).to.equal(
    'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0',
  );
});

test(SUITE, 'NIST FIPS 180-4 §B.5 — SHA-512 of 1,000,000 "a"', () => {
  const buf = Buffer.alloc(1_000_000, 0x61); // 'a'
  expect(createHash('sha512').update(buf).digest('hex')).to.equal(
    'e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b',
  );
});
