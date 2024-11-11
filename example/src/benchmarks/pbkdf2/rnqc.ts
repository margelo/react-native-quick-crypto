import rnqc, { type HashAlgorithm } from 'react-native-quick-crypto';
import type { BenchmarkFn } from '../../types/benchmarks';

const pbkdf2_256_32_32_async: BenchmarkFn = () => {
  rnqc.pbkdf2('password', 'salt', 32, 32, 'sha256', () => {});
};

const pbkdf2_256_32_32_sync: BenchmarkFn = () => {
  rnqc.pbkdf2Sync('password', 'salt', 32, 32, 'sha256' as HashAlgorithm);
};

export default {
  pbkdf2_256_32_32_async,
  pbkdf2_256_32_32_sync,
};
