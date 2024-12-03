import rnqc, { type HashAlgorithm } from 'react-native-quick-crypto';
import * as noble from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha2';
// @ts-expect-error - crypto-browserify is not typed
import browserify from 'crypto-browserify';
import type { BenchFn } from '../../types/benchmarks';
import { Bench } from 'tinybench';

const TIME_MS = 1000;

const pbkdf2_256_1_32_async: BenchFn = () => {
  const bench = new Bench({
    name: 'pbkdf2 sha256 1x 32b (async)',
    time: TIME_MS,
  });

  bench
    .add('rnqc', () => {
      rnqc.pbkdf2('password', 'salt', 1, 32, 'sha256', () => {});
    })
    .add('@noble/hashes/pbkdf2', async () => {
      await noble.pbkdf2Async(sha256, 'password', 'salt', { c: 1, dkLen: 32 });
    })
    .add('browserify/pbkdf2', () => {
      browserify.pbkdf2('password', 'salt', 1, 32, 'sha256', () => {});
    });

  bench.warmupTime = 100;
  return bench;
};

const pbkdf2_256_1_32_sync: BenchFn = () => {
  const bench = new Bench({
    name: 'pbkdf2 sha256 1x 32b (sync)',
    time: TIME_MS,
  });

  bench
    .add('rnqc', () => {
      rnqc.pbkdf2Sync('password', 'salt', 1, 32, 'sha256' as HashAlgorithm);
    })
    .add('@noble/hashes/pbkdf2', () => {
      noble.pbkdf2(sha256, 'password', 'salt', { c: 1, dkLen: 32 });
    })
    .add('browserify/pbkdf2', () => {
      browserify.pbkdf2Sync('password', 'salt', 1, 32, 'sha256');
    });

  bench.warmupTime = 100;
  return bench;
};

export default [pbkdf2_256_1_32_async, pbkdf2_256_1_32_sync];
