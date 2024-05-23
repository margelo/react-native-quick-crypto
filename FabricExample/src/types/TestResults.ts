export type SuiteResults = {
  [key: string]: SuiteResult;
};

export type SuiteResult = {
  results: TestResult[];
};

export type TestResult = {
  type: 'correct' | 'incorrect' | 'grouping';
  description: string;
  errorMsg?: string;
  indentation: number;
  suiteName: string;
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
