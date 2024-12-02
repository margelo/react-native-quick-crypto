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
