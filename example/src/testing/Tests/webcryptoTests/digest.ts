import { expect } from 'chai';
import { Buffer } from '@craftzdog/react-native-buffer';
import QuickCrypto from 'react-native-quick-crypto';
import { describe, it } from '../../MochaRNAdapter';
import type { HashAlgorithm } from '../../../../../src/keys';
import { ab2str, toArrayBuffer } from '../../../../../src/Utils';
import { createHash } from '../../../../../src/Hash';

const { subtle } = QuickCrypto;

type Test = [HashAlgorithm, string, number];

describe('subtle - digest', () => {
  it('empty hash just works, not checking result', async () => {
    await subtle.digest('SHA-512', Buffer.alloc(0));
  });

  const kTests: Test[] = [
    ['SHA-1', 'sha1', 160],
    ['SHA-256', 'sha256', 256],
    ['SHA-384', 'sha384', 384],
    ['SHA-512', 'sha512', 512],
  ];

  const kData = toArrayBuffer(Buffer.from('hello'));

  kTests.map((test): void => {
    it(`hash: ${test[0]}`, async () => {
      const checkValue = createHash(test[1])
        .update(kData)
        .digest()
        .toString('hex');

      const values = Promise.all([
        subtle.digest({ name: test[0] }, kData),
        subtle.digest({ name: test[0], length: test[2] }, kData),
        subtle.digest(test[0], kData),
        // subtle.digest(test[0], kData.buffer),
        // subtle.digest(test[0], new DataView(kData.buffer)),
        subtle.digest(test[0], Buffer.from(kData)),
      ]);

      // Compare that the legacy crypto API and SubtleCrypto API
      // produce the same results
      (await values).forEach((v) => {
        expect(ab2str(v)).to.equal(checkValue);
      });
    });
  });
});
