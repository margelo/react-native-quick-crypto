import type { Bench } from 'tinybench';
import type { BenchFn, BenchmarkResult, SuiteState } from '../types/benchmarks';

export class BenchmarkSuite {
  name: string;
  enabled: boolean;
  benchmarks: BenchFn[];
  state: SuiteState;
  results: BenchmarkResult[] = [];
  notes?: Record<string, string>;

  constructor(
    name: string,
    benchmarks: BenchFn[],
    notes?: Record<string, string>,
  ) {
    this.name = name;
    this.enabled = false;
    this.state = 'idle';
    this.benchmarks = benchmarks;
    this.results = [];
    this.notes = notes;
  }

  addResult(result: BenchmarkResult) {
    this.results.push(result);
  }

  async run() {
    this.results = [];
    // Run benchmarks sequentially to avoid timing interference
    for (const benchFn of this.benchmarks) {
      const b = await benchFn();
      await b.run();
      this.processResults(b);
    }
    this.state = 'done';
  }

  processResults = (b: Bench): void => {
    const tasks = b.tasks;
    const us = tasks.find(t => t.name === 'rnqc');
    const themTasks = tasks.filter(t => t.name !== 'rnqc');

    if (themTasks.length > 0) {
      themTasks.map(them => {
        const notes = this.notes?.[them.name] ?? '';
        this.addResult({
          errorMsg: undefined,
          challenger: them.name,
          notes,
          benchName: b.name,
          them: them.result,
          us: us?.result,
        });
      });
    } else if (us) {
      // No comparison benchmarks, just show rnqc results
      this.addResult({
        errorMsg: undefined,
        challenger: 'N/A',
        notes: '',
        benchName: b.name,
        them: undefined,
        us: us.result,
      });
    }
  };
}
