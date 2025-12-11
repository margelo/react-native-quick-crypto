import rnqc from 'react-native-quick-crypto';
import { sha256 } from '@noble/hashes/sha2';
// @ts-expect-error - crypto-browserify is not typed
import browserify from 'crypto-browserify';
import type { BenchFn } from '../../types/benchmarks';
import { Bench } from 'tinybench';

// Generate test data of different sizes using repeating pattern
const generateString = (sizeInMB: number): string => {
  const chunk =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytesPerMB = 1024 * 1024;
  const totalBytes = Math.floor(sizeInMB * bytesPerMB);
  const repeatCount = Math.ceil(totalBytes / chunk.length);
  return chunk.repeat(repeatCount).substring(0, totalBytes);
};

// Pre-generate test data (8MB as reported in issue)
const text100KB = generateString(0.1);
const text1MB = generateString(1);
const text8MB = generateString(8);

const hash_sha256_8mb: BenchFn = () => {
  const bench = new Bench({
    name: 'hash sha256 8MB string',
    time: 10,
    iterations: 1,
    warmupIterations: 0,
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

const hash_sha256_1mb: BenchFn = () => {
  const bench = new Bench({
    name: 'hash sha256 1MB string',
    time: 50,
    iterations: 2,
    warmupIterations: 0,
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

const hash_sha256_100kb: BenchFn = () => {
  const bench = new Bench({
    name: 'hash sha256 100KB string',
    iterations: 5,
  });

  bench
    .add('rnqc', () => {
      const hash = rnqc.createHash('sha256');
      hash.update(text100KB);
      hash.digest('hex');
    })
    .add('@noble/hashes/sha256', () => {
      sha256(text100KB);
    })
    .add('browserify', () => {
      const hash = browserify.createHash('sha256');
      hash.update(text100KB);
      hash.digest('hex');
    });

  bench.warmupTime = 100;
  return bench;
};

export default [hash_sha256_100kb, hash_sha256_1mb, hash_sha256_8mb];
