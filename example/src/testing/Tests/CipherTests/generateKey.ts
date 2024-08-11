// from https://github.com/nodejs/node/blob/main/test/parallel/test-crypto-secret-keygen.js

import {expect} from 'chai';
import crypto from 'react-native-quick-crypto';
import {describe, it} from '../../MochaRNAdapter';
import type {AESLength} from '../../../../../src/keys';

const {generateKey, generateKeySync} = crypto;

describe('generateKey', () => {
  const badTypes = [1, true, [], {}, Infinity, null, undefined];
  badTypes.forEach(badType => {
    it(`bad type input: ${badType}`, async () => {
      // @ts-expect-error
      expect(() => generateKey(badType, 1, () => {})).to.throw(
        'Unsupported key type',
      );

      // @ts-expect-error
      expect(() => generateKeySync(badType, 1)).to.throw(
        'Unsupported key type',
      );
    });
  });

  const badOptionsAES = ['', true, [], null, undefined];
  badOptionsAES.forEach(badOption => {
    it(`bad option input (aes): ${badOption}`, async () => {
      const expected =
        badOption !== null && badOption !== undefined
          ? 'AES key length must be 128, 192, or 256 bits'
          : "Cannot read property 'length' of " + badOption;

      // @ts-expect-error
      expect(() => generateKey('aes', badOption, () => {})).to.throw(expected);
      // @ts-expect-error
      expect(() => generateKeySync('aes', badOption)).to.throw(expected);
    });
  });

  // const badOptionsHMAC = ['', true, [], null, undefined];
  // badOptionsHMAC.forEach((badOption) => {
  //   it(`bad option input (hmac): ${badOption}`, async () => {
  //     if (badOption !== null && badOption !== undefined) {
  //       // @ts-expect-error
  //       expect(() => generateKey('hmac', badOption, () => {})).to.throw(
  //         'HMAC key length must be between 8 and 2^31 - 1'
  //       );
  //       // @ts-expect-error
  //       expect(() => generateKeySync('hmac', badOption)).to.throw(
  //         'HMAC key length must be between 8 and 2^31 - 1'
  //       );
  //     } else {
  //       // @ts-expect-error
  //       expect(() => generateKey('hmac', badOption, () => {})).to.throw(
  //         `Cannot read property 'length' of ${badOption}`
  //       );
  //       // @ts-expect-error
  //       expect(() => generateKeySync('hmac', badOption)).to.throw(
  //         `Cannot read property 'length' of ${badOption}`
  //       );
  //     }
  //   });
  // });

  it('bad callback (aes)', async () => {
    // @ts-expect-error
    expect(() => generateKey('aes', {length: 256})).to.throw(
      'Callback is not a function',
    );
  });

  const hmacBadLengths = [-1, 4, 7, 2 ** 31];
  hmacBadLengths.forEach(badLength => {
    it(`bad option length (hmac): ${badLength}`, async () => {
      expect(() =>
        // @ts-expect-error
        generateKey('hmac', {length: badLength}, () => {}),
      ).to.throw('HMAC key length must be between 8 and 2^31 - 1');
      // @ts-expect-error
      expect(() => generateKeySync('hmac', {length: badLength})).to.throw(
        'HMAC key length must be between 8 and 2^31 - 1',
      );
    });
  });

  const aesLengths: AESLength[] = [128, 192, 256];
  aesLengths.forEach(length => {
    it(`happy generateKeySync (aes): ${length}`, async () => {
      const key = generateKeySync('aes', {length});
      expect(key).to.not.be.undefined;
      const keybuf = key.export();
      expect(keybuf.byteLength).to.equal(length / 8);
    });
    it(`happy generateKey (aes): ${length}`, async () => {
      generateKey('aes', {length}, (err, key) => {
        expect(err).to.be.undefined;
        expect(key).to.not.be.undefined;
        const keybuf = key?.export();
        expect(keybuf?.byteLength).to.equal(length / 8);
      });
    });
  });

  // TODO: copied from node, no edits yet - fix when we implement HMAC
  // const key = generateKeySync('hmac', { length: 123 });
  // assert(key);
  // const keybuf = key.export();
  // assert.strictEqual(keybuf.byteLength, Math.floor(123 / 8));

  // generateKey('hmac', { length: 123 }, common.mustSucceed((key) => {
  //   assert(key);
  //   const keybuf = key.export();
  //   assert.strictEqual(keybuf.byteLength, Math.floor(123 / 8));
  // }));
});
