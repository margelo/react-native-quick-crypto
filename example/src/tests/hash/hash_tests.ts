/**
 * Tests are based on Node.js tests
 * https://github.com/nodejs/node/blob/master/test/parallel/test-crypto-hash.js
 */

import { Buffer } from '@craftzdog/react-native-buffer';
import {
  createHash,
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
  expect(algorithms).to.be.an('array');
  console.log(algorithms);
  expect(algorithms).to.deep.equal([
    'SHA3-512',
    'SHA2-512/256',
    'SHA2-224',
    'SHA1',
    'SHA3-224',
    'SHA3-384',
    'RIPEMD-160',
    'SHA2-512',
    'SHA2-512/224',
    'SHAKE-256',
    'SHA2-384',
    'SM3',
    'SHA3-256',
    'MD5',
    'BLAKE2S-256',
    'SHA2-256',
    'BLAKE2B-512',
    'MD5-SHA1',
    'SHAKE-128',
    'SHA2-256/192',
    'KECCAK-224',
    'KECCAK-256',
    'KECCAK-384',
    'KECCAK-512',
    'KECCAK-KMAC-128',
    'KECCAK-KMAC-256',
    'NULL',
  ]);
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
  }).to.throw(/Value is an object/);
});
test(SUITE, 'update - calling update without argument', () => {
  const hash = createHash('sha256');
  expect(() => {
    // @ts-expect-error calling update without argument
    hash.update();
  }).to.throw(/input could not be converted/);
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
