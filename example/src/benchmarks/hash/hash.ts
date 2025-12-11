import rnqc from 'react-native-quick-crypto';
import { sha256 } from '@noble/hashes/sha2';
// @ts-expect-error - crypto-browserify is not typed
import browserify from 'crypto-browserify';
import type { BenchFn } from '../../types/benchmarks';
import { Bench } from 'tinybench';
import { text1MB, text8MB, buffer1MB, buffer8MB } from '../testData';

const hash_sha256_8mb_string: BenchFn = () => {
  const bench = new Bench({
    name: 'hash sha256 8MB string',
    iterations: 3,
    warmupIterations: 1,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      const hash = rnqc.createHash('sha256');
      hash.update(text8MB);
      hash.digest('hex');
    })
    .add('@noble/hashes/sha256', () => {
      sha256(text8MB);
    })
    .add('browserify', () => {
      const hash = browserify.createHash('sha256');
      hash.update(text8MB);
      hash.digest('hex');
    });

  return bench;
};

const hash_sha256_1mb_string: BenchFn = () => {
  const bench = new Bench({
    name: 'hash sha256 1MB string',
    iterations: 5,
    warmupIterations: 2,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      const hash = rnqc.createHash('sha256');
      hash.update(text1MB);
      hash.digest('hex');
    })
    .add('@noble/hashes/sha256', () => {
      sha256(text1MB);
    })
    .add('browserify', () => {
      const hash = browserify.createHash('sha256');
      hash.update(text1MB);
      hash.digest('hex');
    });

  return bench;
};

const hash_sha256_8mb_buffer: BenchFn = () => {
  const bench = new Bench({
    name: 'hash sha256 8MB Buffer',
    iterations: 3,
    warmupIterations: 1,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      const hash = rnqc.createHash('sha256');
      hash.update(buffer8MB);
      hash.digest('hex');
    })
    .add('@noble/hashes/sha256', () => {
      sha256(buffer8MB);
    })
    .add('browserify', () => {
      const hash = browserify.createHash('sha256');
      hash.update(buffer8MB);
      hash.digest('hex');
    });

  return bench;
};

const hash_sha256_1mb_buffer: BenchFn = () => {
  const bench = new Bench({
    name: 'hash sha256 1MB Buffer',
    iterations: 5,
    warmupIterations: 2,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      const hash = rnqc.createHash('sha256');
      hash.update(buffer1MB);
      hash.digest('hex');
    })
    .add('@noble/hashes/sha256', () => {
      sha256(buffer1MB);
    })
    .add('browserify', () => {
      const hash = browserify.createHash('sha256');
      hash.update(buffer1MB);
      hash.digest('hex');
    });

  return bench;
};

export default [
  hash_sha256_1mb_string,
  hash_sha256_1mb_buffer,
  hash_sha256_8mb_string,
  hash_sha256_8mb_buffer,
];
