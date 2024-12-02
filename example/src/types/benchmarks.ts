import type { Bench, TaskResult } from 'tinybench';

export type BenchFn = () => Bench | Promise<Bench>;

export type SuiteState = 'idle' | 'running' | 'done';

export type Challenger = {
  name: string;
  notes: string;
  // fn: BenchmarkFn;
};

export type BenchmarkResult = {
  errorMsg?: string;
  challenger?: string;
  notes?: string;
  benchName: string | undefined;
  them: Readonly<TaskResult> | undefined;
  us: Readonly<TaskResult> | undefined;
};
