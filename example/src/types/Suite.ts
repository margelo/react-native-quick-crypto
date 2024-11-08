import type { BenchmarkFn } from '../benchmarks/types';

export type Suites<T = TestSuite | BenchmarkSuite> = {
  [key: string]: T;
};

export interface Suite {
  value: boolean;
}

// test types
export interface Tests {
  [key: string]: () => void;
}

export interface TestSuite extends Suite {
  tests: Tests;
}

// benchmark types
export type Benchmark = {
  us?: BenchmarkFn;
  them?: BenchmarkFn;
};

export interface Benchmarks {
  [key: string]: Benchmark;
}

export interface BenchmarkSuite extends Suite {
  benchmarks: Benchmarks;
}
