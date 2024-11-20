import rnqc, { type HashAlgorithm } from 'react-native-quick-crypto';
import * as noble from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha2';
// @ts-expect-error - crypto-browserify is not typed
import browserify from 'crypto-browserify';

import type { ImportedBenchmark } from '../../types/benchmarks';

export const pbkdf2_256_1_32_async: ImportedBenchmark = {
  name: 'pbkdf2_256_1_32_async',
  runCount: 1000,
  us: () => rnqc.pbkdf2('password', 'salt', 1, 32, 'sha256', () => {}),
  them: [
    {
      name: '@noble/hashes/pbkdf2',
      notes: '',
      fn: () => noble.pbkdf2Async(sha256, 'password', 'salt', { c: 1, dkLen: 32 }),
    },
    {
      name: 'browserify/pbkdf2',
      notes: '',
      fn: () => browserify.pbkdf2('password', 'salt', 1, 32, 'sha256', () => {}),
    },
  ],
};

export const pbkdf2_256_1_32_sync: ImportedBenchmark = {
  name: 'pbkdf2_256_1_32_sync',
  runCount: 1000,
  us: () => rnqc.pbkdf2Sync('password', 'salt', 1, 32, 'sha256' as HashAlgorithm),
  them: [
    {
      name: '@noble/hashes/pbkdf2',
      notes: '',
      fn: () => noble.pbkdf2(sha256, 'password', 'salt', { c: 1, dkLen: 32 }),
    },
    {
      name: 'browserify/pbkdf2',
      notes: '',
      fn: () => browserify.pbkdf2Sync('password', 'salt', 1, 32, 'sha256'),
    },
  ],
};
