import { test } from '../util';
import {
  generatePrime,
  generatePrimeSync,
  checkPrime,
  checkPrimeSync,
  Buffer,
} from 'react-native-quick-crypto';
import { assert } from 'chai';

const SUITE = 'prime';

test(
  SUITE,
  'generatePrimeSync: generates a prime of requested bit size',
  () => {
    const prime = generatePrimeSync(128);
    assert.isOk(prime);
    assert.isTrue(Buffer.isBuffer(prime));
    // 128-bit prime should be 16 bytes (possibly 15 or 17 due to leading zeros)
    const len = (prime as Buffer).length;
    assert.isTrue(len >= 15 && len <= 17);
  },
);

test(SUITE, 'generatePrimeSync: bigint option returns bigint', () => {
  const prime = generatePrimeSync(64, { bigint: true });
  assert.strictEqual(typeof prime, 'bigint');
  assert.isTrue((prime as bigint) > 0n);
});

test(SUITE, 'generatePrimeSync: safe prime option', () => {
  const prime = generatePrimeSync(64, { safe: true, bigint: true });
  assert.strictEqual(typeof prime, 'bigint');
  assert.isTrue((prime as bigint) > 0n);
});

test(SUITE, 'checkPrimeSync: known prime returns true', () => {
  const result = checkPrimeSync(Buffer.from([0x07]));
  assert.isTrue(result);
});

test(SUITE, 'checkPrimeSync: known composite returns false', () => {
  const result = checkPrimeSync(Buffer.from([0x04]));
  assert.isFalse(result);
});

test(SUITE, 'checkPrimeSync: verifies generated prime', () => {
  const prime = generatePrimeSync(128);
  const result = checkPrimeSync(prime as Buffer);
  assert.isTrue(result);
});

test(SUITE, 'generatePrime: async generates a prime', () => {
  return new Promise<void>((resolve, reject) => {
    generatePrime(64, (err, prime) => {
      try {
        assert.isNull(err);
        assert.isOk(prime);
        assert.isTrue(Buffer.isBuffer(prime));
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
});

test(SUITE, 'checkPrime: async checks a prime', () => {
  return new Promise<void>((resolve, reject) => {
    const prime = generatePrimeSync(64);
    checkPrime(prime as Buffer, (err, result) => {
      try {
        assert.isNull(err);
        assert.isTrue(result);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
});

test(SUITE, 'checkPrimeSync: bigint input', () => {
  assert.isTrue(checkPrimeSync(7n));
  assert.isFalse(checkPrimeSync(4n));
});
