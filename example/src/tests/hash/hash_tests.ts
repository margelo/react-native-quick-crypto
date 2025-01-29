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
test(SUITE, 'digest with hex argument', () => {
  expect(createHash('sha1').update('Test123').digest('hex')).to.equal(
    '8308651804facb7b9af8ffc53a33a22d6a1c8ac2',
  );
});
test(SUITE, 'digest with base64 argument', () => {
  expect(createHash('sha256').update('Test123').digest('base64')).to.equal(
    '2bX1jws4GYKTlxhloUB09Z66PoJZW+y+hq5R8dnx9l4=',
  );
});
test(SUITE, 'digest without argument defaults to buffer', () => {
  expect(createHash('sha512').update('Test123').digest()).to.deep.equal(
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
test(SUITE, 'digest with buffer argument', () => {
  expect(createHash('sha1').update('Test123').digest('buffer')).to.deep.equal(
    Buffer.from('8308651804facb7b9af8ffc53a33a22d6a1c8ac2', 'hex'),
  );
});
