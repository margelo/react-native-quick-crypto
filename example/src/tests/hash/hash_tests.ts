/**
 * Tests are based on Node.js tests
 * https://github.com/nodejs/node/blob/master/test/parallel/test-crypto-hash.js
 */

import { Buffer } from '@craftzdog/react-native-buffer';
import { createHash } from 'react-native-quick-crypto';
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
const a1 = createHash('sha1').update('Test123').digest('hex');
const a2 = createHash('sha256').update('Test123').digest('base64');
const a3 = createHash('sha512').update('Test123').digest(); // buffer
const a4 = createHash('sha1').update('Test123').digest('buffer');

test(SUITE, 'non stream - digest with hex argument', () => {
  expect(a1).to.equal('8308651804facb7b9af8ffc53a33a22d6a1c8ac2');
});
test(SUITE, 'non stream - digest with base64 argument', () => {
  expect(a2).to.equal('2bX1jws4GYKTlxhloUB09Z66PoJZW+y+hq5R8dnx9l4=');
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

// stream interface
let a5 = createHash('sha512');
a5.end('Test123');
a5 = a5.read();

test(SUITE, 'stream - should produce the same output as non-stream', () => {
  expect(a5).to.deep.equal(a3);
});
