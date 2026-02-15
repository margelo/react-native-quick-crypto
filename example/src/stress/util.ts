import type { TestSuites } from '../types/tests';

export const StressContext: TestSuites = {};

export const stress = (
  suiteName: string,
  testName: string,
  fn: () => void | Promise<void>,
): void => {
  if (!StressContext[suiteName]) {
    StressContext[suiteName] = { value: false, tests: {} };
  }
  StressContext[suiteName].tests[testName] = fn;
};
