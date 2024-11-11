import type { Suite } from "./suite";

export interface BenchmarkSuite extends Suite {
  benchmarks: Benchmarks;
}

export interface Benchmarks {
  [key: string]: Benchmark;
}

export type BenchmarkFn = () => void;

export type Benchmark = {
  us?: UsRandom | UsPbkdf2;
  them?: ThemRandom[] | ThemPbkdf2[];
};

// random
export type UsRandom = {
  randomBytes10: BenchmarkFn;
  randomBytes1024: BenchmarkFn;
};

export type ThemRandom = {
  challenger: string;
  notes: string;
  randomBytes10: BenchmarkFn;
  randomBytes1024: BenchmarkFn;
};

// pbkdf2
export type UsPbkdf2 = {
  pbkdf2_256_32_32_async: BenchmarkFn;
  pbkdf2_256_32_32_sync: BenchmarkFn;
};

export type ThemPbkdf2 = {
  challenger: string;
  notes: string;
  pbkdf2_256_32_32_async: BenchmarkFn;
  pbkdf2_256_32_32_sync: BenchmarkFn;
};
