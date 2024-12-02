import rnqc from 'react-native-quick-crypto';
// @ts-expect-error - crypto-browserify is not typed
import browserify from 'crypto-browserify';
import type { BenchFn } from '../../types/benchmarks';
import { Bench } from 'tinybench';

const TIME_MS = 1000;

const randomBytes10: BenchFn = () => {
  const bench = new Bench({
    name: 'randomBytes10',
    time: TIME_MS,
  });

  bench
    .add('rnqc', () => {
      rnqc.randomBytes(10);
    })
    .add('crypto-browserify', () => browserify.randomBytes(10));

  bench.warmupTime = 100;
  return bench;
};

const randomBytes1024: BenchFn = () => {
  const bench = new Bench({
    name: 'randomBytes1024',
    time: TIME_MS,
  });

  bench
    .add('rnqc', () => rnqc.randomBytes(1024))
    .add('crypto-browserify', () => browserify.randomBytes(1024));
  bench.warmupTime = 100;

  return bench;
};

export default [randomBytes10, randomBytes1024];
