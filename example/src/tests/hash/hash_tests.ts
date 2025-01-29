import { expect } from 'chai';
import { createHash } from 'react-native-quick-crypto';
import { test } from '../util';

const SUITE = 'hash';

test(SUITE, 'valid algorithm', () => {
  expect(() => {
    createHash('sha256');
  }).to.not.throw();
});

test(SUITE, 'invalid algorithm', () => {
  expect(() => {
    createHash('sha123');
  }).to.throw(/Unknown hash algorithm: sha123/);
});

test(SUITE, 'valid update and digest', () => {
  const hash = createHash('sha256').update('test').digest('hex');
  expect(hash).to.equal('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
});