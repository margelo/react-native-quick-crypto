import rnqc from 'react-native-quick-crypto';
import type { BenchmarkFn } from '../types';

const randomBytes10: BenchmarkFn = () => {
  rnqc.randomBytes(10);
};

const randomBytes1024: BenchmarkFn = () => {
  rnqc.randomBytes(1024);
};

export default {
  randomBytes10,
  randomBytes1024,
};
