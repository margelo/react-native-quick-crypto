export interface TestResult {
  name: string;
  status: 'correct' | 'incorrect' | 'error';
  key: string;
  errorMsg?: string;
}
