import type { BenchmarkFn } from '../benchmarks/types';

export type Suites<T = TestSuite | BenchmarkSuite> = {
  [key: string]: T;
};

export interface TestSuite {
  value: boolean;
  tests: Tests;
}

export interface Tests {
  [key: string]: () => void;
}

export interface BenchmarkSuite extends TestSuite {
  benchmarks: Benchmark[];
}

export type Benchmark = {
  name: string;
  us?: BenchmarkFn;
  them?: BenchmarkFn;
};
