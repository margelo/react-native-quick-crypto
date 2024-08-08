export type Suites<T = TestSuite | BenchmarkSuite> = {
  [key: string]: T;
};

export interface TestSuite {
  value: boolean;
  count: number;
};

export interface BenchmarkSuite extends TestSuite {
  us: Record<string, Function>;
  them: Record<string, Function>;
};
