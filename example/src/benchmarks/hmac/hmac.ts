import rnqc from 'react-native-quick-crypto';
// @ts-expect-error - crypto-browserify is not typed
import browserify from 'crypto-browserify';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';
import type { BenchFn } from '../../types/benchmarks';
import { Bench } from 'tinybench';
import { text1MB, text8MB, buffer1MB, buffer8MB } from '../testData';

const hmacKey = 'test-key-for-hmac-benchmarks';

const hmac_sha256_8mb_string: BenchFn = () => {
  const bench = new Bench({
    name: 'hmac sha256 8MB string',
    iterations: 3,
    warmupIterations: 1,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      const h = rnqc.createHmac('sha256', hmacKey);
      h.update(text8MB);
      h.digest('hex');
    })
    .add('@noble/hashes/hmac', () => {
      hmac(sha256, hmacKey, text8MB);
    })
    .add('browserify', () => {
      const h = browserify.createHmac('sha256', hmacKey);
      h.update(text8MB);
      h.digest('hex');
    });

  return bench;
};

const hmac_sha256_1mb_string: BenchFn = () => {
  const bench = new Bench({
    name: 'hmac sha256 1MB string',
    iterations: 5,
    warmupIterations: 2,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      const h = rnqc.createHmac('sha256', hmacKey);
      h.update(text1MB);
      h.digest('hex');
    })
    .add('@noble/hashes/hmac', () => {
      hmac(sha256, hmacKey, text1MB);
    })
    .add('browserify', () => {
      const h = browserify.createHmac('sha256', hmacKey);
      h.update(text1MB);
      h.digest('hex');
    });

  return bench;
};

const hmac_sha256_8mb_buffer: BenchFn = () => {
  const bench = new Bench({
    name: 'hmac sha256 8MB Buffer',
    iterations: 3,
    warmupIterations: 1,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      const h = rnqc.createHmac('sha256', hmacKey);
      h.update(buffer8MB);
      h.digest('hex');
    })
    .add('@noble/hashes/hmac', () => {
      hmac(sha256, hmacKey, buffer8MB);
    })
    .add('browserify', () => {
      const h = browserify.createHmac('sha256', hmacKey);
      h.update(buffer8MB);
      h.digest('hex');
    });

  return bench;
};

const hmac_sha256_1mb_buffer: BenchFn = () => {
  const bench = new Bench({
    name: 'hmac sha256 1MB Buffer',
    iterations: 5,
    warmupIterations: 2,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      const h = rnqc.createHmac('sha256', hmacKey);
      h.update(buffer1MB);
      h.digest('hex');
    })
    .add('@noble/hashes/hmac', () => {
      hmac(sha256, hmacKey, buffer1MB);
    })
    .add('browserify', () => {
      const h = browserify.createHmac('sha256', hmacKey);
      h.update(buffer1MB);
      h.digest('hex');
    });

  return bench;
};

export default [
  hmac_sha256_1mb_string,
  hmac_sha256_1mb_buffer,
  hmac_sha256_8mb_string,
  hmac_sha256_8mb_buffer,
];
