import { expect } from 'chai';
import crypto from 'react-native-quick-crypto';
import { describe, it } from '../../MochaRNAdapter';
import { ab2str } from '../../../../../src/Utils';
import type { HashAlgorithm } from '../../../../../src/keys';

const { subtle } = crypto;

type TestFixture = [string, string, number, HashAlgorithm, number, string];

describe('subtle.deriveBits()', () => {
  // pbkdf2 deriveBits()
  // {
  const test = async (
    pass: string,
    salt: string,
    iterations: number,
    hash: HashAlgorithm,
    length: number,
    expected: string
  ) => {
    const key = await subtle.importKey(
      'raw',
      pass,
      { name: 'PBKDF2', hash },
      false,
      ['deriveBits']
    );

    const bits = await subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations,
        hash,
      },
      key,
      length
    );
    expect(ab2str(bits)).to.equal(expected);
  };

  const kTests: TestFixture[] = [
    [
      'hello',
      'there',
      10,
      'SHA-256',
      512,
      'f72d1cf4853fffbd16a42751765d11f8dc7939498ee7b7' +
        'ce7678b4cb16fad88098110a83e71f4483ce73203f7a64' +
        '719d293280f780f9fafdcf46925c5c0588b3',
    ],
    ['hello', 'there', 5, 'SHA-384', 128, '201509b012c9cd2fbe7ea938f0c509b3'],
  ];

  kTests.forEach(async ([pass, salt, iterations, hash, length, expected]) => {
    it(`PBKDF2 importKey raw/deriveBits - ${pass} ${salt} ${iterations} ${hash} ${length}`, async () => {
      await test(pass, salt, iterations, hash, length, expected);
    });
  });
  // }

  // ecdh deriveBits
  // {}
});
