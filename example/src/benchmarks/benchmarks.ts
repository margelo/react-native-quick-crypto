import type { Bench } from 'tinybench';
import type { BenchFn, BenchmarkResult, SuiteState } from '../types/benchmarks';

export class BenchmarkSuite {
  name: string;
  enabled: boolean;
  benchmarks: BenchFn[];
  state: SuiteState;
  results: BenchmarkResult[] = [];

  constructor(name: string, benchmarks: BenchFn[]) {
    this.name = name;
    this.enabled = false;
    this.state = 'idle';
    this.benchmarks = benchmarks;
    this.results = [];
  }

  addResult(result: BenchmarkResult) {
    this.results.push(result);
  }

  async run() {
    this.results = [];
    const promises = this.benchmarks.map(async benchFn => {
      const b = await benchFn();
      await b.run();
      this.processResults(b);
      this.state = 'done';
    });
    await Promise.all(promises);
  }

  processResults = (b: Bench): void => {
    const tasks = b.tasks;
    const us = tasks.find(t => t.name === 'rnqc');
    const themTasks = tasks.filter(t => t.name !== 'rnqc');

    themTasks.map(them => {
      this.addResult({
        errorMsg: undefined,
        challenger: them.name,
        notes: '',
        benchName: b.name,
        them: them.result,
        us: us?.result,
      });
    });
  };
}
