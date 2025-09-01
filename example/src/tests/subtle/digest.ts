import { expect } from 'chai';
import { Buffer } from '@craftzdog/react-native-buffer';
import {
  subtle,
  ab2str,
  toArrayBuffer,
  type HashAlgorithm,
  createHash,
} from 'react-native-quick-crypto';
import { test } from '../util';

type Test = [HashAlgorithm, string, number];

const SUITE = 'subtle.digest';
test(SUITE, 'empty hash just works', async () => {
  await subtle.digest('SHA-512', Buffer.alloc(0));
});

const kTests: Test[] = [
  ['SHA-1', 'sha1', 160],
  ['SHA-256', 'sha256', 256],
  ['SHA-384', 'sha384', 384],
  ['SHA-512', 'sha512', 512],
];

const kData = toArrayBuffer(Buffer.from('hello'));

kTests.forEach(([algorithm, legacyName, bitLength]) => {
  test(SUITE, `hash: ${algorithm}`, async () => {
    const checkValue = createHash(legacyName)
      .update(kData)
      .digest()
      .toString('hex');

    const values = await Promise.all([
      subtle.digest({ name: algorithm }, kData),
      subtle.digest({ name: algorithm, length: bitLength }, kData),
      subtle.digest(algorithm, kData),
      subtle.digest(algorithm, Buffer.from(kData)),
    ]);

    // Compare that the legacy crypto API and SubtleCrypto API
    // produce the same results
    values.forEach(v => {
      expect(ab2str(v)).to.equal(checkValue);
    });
  });
});
