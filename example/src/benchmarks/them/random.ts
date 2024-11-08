// @ts-expect-error - crypto-browserify is not typed
import { randomBytes } from 'crypto-browserify';
import type { BenchmarkFn } from '../types';

const randomBytes10: BenchmarkFn = () => {
  randomBytes(10);
};

const randomBytes1024: BenchmarkFn = () => {
  randomBytes(1024);
};

export default {
  randomBytes10,
  randomBytes1024,
};
