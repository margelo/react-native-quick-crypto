// @ts-expect-error - crypto-browserify is not typed
import { randomBytes } from 'crypto-browserify';
import type { BenchmarkFn, ThemRandom } from '../../types/benchmarks';

const challenger = 'crypto-browserify';

const notes = `
  '${challenger}' uses 'globalThis.crypto' under the hood, which on RN is this
  library, if polyfilled.  So this benchmark doesn't make a lot of sense.
`;

const randomBytes10: BenchmarkFn = () => {
  randomBytes(10);
};

const randomBytes1024: BenchmarkFn = () => {
  randomBytes(1024);
};

const benchmark: ThemRandom = {
  challenger,
  notes,
  randomBytes10,
  randomBytes1024,
};

export default benchmark;
