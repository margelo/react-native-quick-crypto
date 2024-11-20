import rnqc from 'react-native-quick-crypto';
// @ts-expect-error - crypto-browserify is not typed
import browserify from 'crypto-browserify';
import type { ImportedBenchmark } from '../../types/benchmarks';

export const randomBytes10: ImportedBenchmark = {
  name: 'randomBytes10',
  runCount: 100000,
  us: () => rnqc.randomBytes(10),
  them: [
    {
      name: 'crypto-browserify',
      notes: `'crypto-browserify' uses 'globalThis.crypto' under the hood, which on RN is this
        library, if polyfilled.  So this benchmark doesn't make a lot of sense.
      `,
      fn: () => browserify.randomBytes(10)
    },
  ],
};

export const randomBytes1024: ImportedBenchmark = {
  name: 'randomBytes1024',
  runCount: 50000,
  us: () => rnqc.randomBytes(1024),
  them: [
    {
      name: 'crypto-browserify',
      notes: `'crypto-browserify' uses 'globalThis.crypto' under the hood, which on RN is this
        library, if polyfilled.  So this benchmark doesn't make a lot of sense.
      `,
      fn: () => browserify.randomBytes(1024)
    },
  ],
};
