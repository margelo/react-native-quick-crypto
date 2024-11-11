import type { Suites, TestSuite } from '../types/suite';

export const TestsContext: Suites<TestSuite> = {};

export const test = (
  suiteName: string,
  testName: string,
  fn: () => void,
): void => {
  if (!TestsContext[suiteName]) {
    TestsContext[suiteName] = { value: false, tests: {} };
  }
  TestsContext[suiteName].tests[testName] = fn;
};
