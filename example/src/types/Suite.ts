export type Suites<T = TestSuite | BenchmarkSuite> = {
  [key: string]: T;
};

export interface TestSuite {
  value: boolean;
  count: number;
};

export interface BenchmarkSuite extends TestSuite {
  benchmarks: Benchmark[];
};

export type Benchmark = {
  name: string;
  us?: Function;
  them?: Function;
};
