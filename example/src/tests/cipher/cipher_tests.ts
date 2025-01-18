import {
  Cipher,
  getCiphers,
  createCipheriv,
  randomFillSync,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';

const SUITE = 'cipher';
const key = 'secret';
const iv = randomFillSync(new Uint8Array(16));

test(SUITE, 'cipher - valid algorithm', async () => {
  const cipher = createCipheriv('aes-128-cbc', key, iv, {});
  expect(cipher).to.be.instanceOf(Cipher);
});

test(SUITE, 'cipher - invalid algorithm', async () => {
  expect(() => {
    // @ts-expect-error - testing bad algorithm
    createCipheriv('aes-128-boorad', key, iv, {});
  }).to.throw(/Invalid Cipher Algorithm: aes-128-boorad/);
});

test(SUITE, 'cipher - getSupportedCiphers', async () => {
  const ciphers = getCiphers();
  expect(ciphers).to.be.instanceOf(Array);
  expect(ciphers).to.have.length.greaterThan(0);
});
