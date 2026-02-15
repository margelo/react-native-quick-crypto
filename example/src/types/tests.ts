export type TestSuites = {
  [key: string]: TestSuite;
};

export interface TestSuite {
  value: boolean;
  tests: Tests;
}

export interface Tests {
  [key: string]: () => void | Promise<void>;
}

export interface SuiteEntry {
  name: string;
  suite: TestSuite;
  count: number;
}
