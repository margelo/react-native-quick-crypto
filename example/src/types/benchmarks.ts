export type ImportedBenchmark = {
  name: string;
  runCount: number;
  us: BenchmarkFn;
  them: Challenger[];
}

export type SuiteState = 'idle' | 'running' | 'done';

export type BenchmarkFn = () => void;

export type Challenger = {
  name: string;
  notes: string;
  fn: BenchmarkFn;
};
