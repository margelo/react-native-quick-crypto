import type { TestResult } from '../../../types/TestResults';

export type TestingScreenProps = {
  results: TestResult[];
  suiteName: string;
};
