import type { BenchmarkSuite } from "./benchmarks";
import type { TestSuite } from "./tests";

export type Suites<T = TestSuite | BenchmarkSuite> = {
  [key: string]: T;
};

export interface Suite {
  value: boolean;
}
