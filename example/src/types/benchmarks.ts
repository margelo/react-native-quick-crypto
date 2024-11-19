import type { Suite } from "./suite";

export interface BenchmarkSuite extends Suite {
  name: string;
  benchmarks: Benchmark[];
}

export type Benchmark = Record<AllLibs, AllImports>[];

export type AllImports =
  | UsRandom
  | UsPbkdf2
  | ThemRandom
  | ThemPbkdf2
  ;

export type AllLibs = 'rnqc' | 'browserify' | 'noble';

export type BenchmarkImports = {
  random: Benchmark[];
  pbkdf2: Benchmark[];
};

export type BenchmarkFn = () => void;
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
  pbkdf2_256_1_32_async: BenchmarkFn;
  pbkdf2_256_1_32_sync: BenchmarkFn;
};

export type ThemPbkdf2 = {
  challenger: string;
  notes: string;
  pbkdf2_256_1_32_async: BenchmarkFn;
  pbkdf2_256_1_32_sync: BenchmarkFn;
};
