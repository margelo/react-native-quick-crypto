import { expect } from 'chai';
import { createHash } from 'react-native-quick-crypto';
import { test } from '../util';

const SUITE = 'hash';

test(SUITE, 'valid algorithm', async () => {
  expect(() => {
    createHash('sha256');
  }).to.not.throw();
});

test(SUITE, 'invalid algorithm', async () => {
  expect(() => {
    createHash('sha123');
  }).to.throw(/Unknown hash algorithm: sha123/);
});

function _roundtrip(algorithm: string, payload: string) {
  const hash = createHash(algorithm);
  hash.update(payload);
  const digest = hash.digest('hex');

  console.log({ algorithm, payload, digest });

  return hash;
}
