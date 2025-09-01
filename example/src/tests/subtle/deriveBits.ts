import { expect } from 'chai';
import {
  subtle,
  ab2str,
  type HashAlgorithm,
  normalizeHashName,
} from 'react-native-quick-crypto';
import { test } from '../util';

type TestFixture = [
  string,
  string,
  number,
  HashAlgorithm | string,
  number,
  string,
];

const SUITE = 'subtle.deriveBits';

// pbkdf2 deriveBits()
// {
const test_fn = async (
  pass: string,
  salt: string,
  iterations: number,
  hash: HashAlgorithm | string,
  length: number,
  expected: string,
) => {
  const key = await subtle.importKey(
    'raw',
    pass,
    { name: 'PBKDF2', hash: normalizeHashName(hash) },
    false,
    ['deriveBits'],
  );

  const bits = await subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: normalizeHashName(hash),
    },
    key,
    length,
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
  test(
    SUITE,
    `PBKDF2 importKey raw/deriveBits - ${pass} ${salt} ${iterations} ${hash} ${length}`,
    async () => {
      await test_fn(pass, salt, iterations, hash, length, expected);
    },
  );
});

// ecdh deriveBits
