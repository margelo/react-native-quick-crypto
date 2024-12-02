import type { TestSuites } from '../types/tests';

export const TestsContext: TestSuites = {};

export const test = (
  suiteName: string,
  testName: string,
  fn: () => void | Promise<void>,
): void => {
  if (!TestsContext[suiteName]) {
    TestsContext[suiteName] = { value: false, tests: {} };
  }
  TestsContext[suiteName].tests[testName] = fn;
};
