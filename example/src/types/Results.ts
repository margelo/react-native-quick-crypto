export type SuiteResults<T = TestResult | BenchmarkResult> = {
  [key: string]: SuiteResult<T>;
};

export type SuiteResult<T> = {
  results: T[];
};

export type TestResult = {
  type: 'correct' | 'incorrect' | 'grouping';
  description: string;
  errorMsg?: string;
  indentation: number;
  suiteName: string;
};

// export type BenchmarkResult = {
//   suiteName: string;
//   results: FnResult[];
// };

export type BenchmarkResult = {
  errorMsg?: string;
  libName: string;
  challenger?: string;
  notes?: string;
  fnName: string;
  time: number;
  us?: number;
  type?: 'faster' | 'slower';
};

export type Stats = {
  start: Date;
  end: Date;
  duration: number;
  suites: number;
  tests: number;
  passes: number;
  pending: number;
  failures: number;
};
