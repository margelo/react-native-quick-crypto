// @ts-expect-error - crypto-browserify is not typed
import { pbkdf2, pbkdf2Sync } from 'crypto-browserify';
import type { BenchmarkFn, ThemPbkdf2 } from '../../types/benchmarks';

const challenger = 'browserify/pbkdf2';

const notes = ``;

const pbkdf2_256_1_32_async: BenchmarkFn = () => {
  pbkdf2('password', 'salt', 1, 32, 'sha256', () => {});
};

const pbkdf2_256_1_32_sync: BenchmarkFn = () => {
  pbkdf2Sync('password', 'salt', 1, 32, 'sha256');
};

const benchmark: ThemPbkdf2 = {
  challenger,
  notes,
  pbkdf2_256_1_32_async,
  pbkdf2_256_1_32_sync,
};

export default benchmark;
