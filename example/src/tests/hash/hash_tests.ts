import { expect } from 'chai';
import { createHash } from 'react-native-quick-crypto';
import { test } from '../util';

const SUITE = 'hash';

test(SUITE, 'valid algorithm', async () => {
  expect(() => {
    createHash('sha256')
  }).to.not.throw();
});

test(SUITE, 'invalid algorithm', async () => {
  expect(() => {
    createHash('sha123')
  }).to.throw(/Unknown hash algorithm: sha123/);
});