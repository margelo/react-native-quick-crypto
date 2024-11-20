import type {
  BenchmarkFn,
  BenchmarkResult,
  Challenger,
  ImportedBenchmark,
  SuiteState,
} from '../types/benchmarks';
import { calculateTimes } from './utils';

export class BenchmarkSuite {
  name: string;
  enabled: boolean;
  benchmarks: Benchmark[];
  state: SuiteState;
  results: BenchmarkResult[] = [];

  constructor(name: string) {
    this.name = name;
    this.enabled = false;
    this.state = 'idle';
    this.benchmarks = [];
    this.results = [];
  }

  addBenchmark(imported: ImportedBenchmark) {
    this.benchmarks.push(new Benchmark(imported));
  }

  addResult(result: BenchmarkResult) {
    this.results.push(result);
  }

  run(multiplier: number = 1) {
    this.results = [];
    this.benchmarks.forEach(benchmark => {
      benchmark.run(this, multiplier);
    });
  }
}

export class Benchmark {
  name: string; // function name
  runCount: number;
  us?: BenchmarkFn;
  them: Challenger[];

  constructor(benchmark: ImportedBenchmark) {
    this.name = benchmark.name;
    this.runCount = benchmark.runCount;
    this.us = benchmark.us;
    this.them = benchmark.them;
  }

  run(suite: BenchmarkSuite, multiplier: number = 1) {
    const usTime = this.timeFn(this.us!, multiplier);
    this.them.forEach(them => {
      const themTime = this.timeFn(them.fn, multiplier);
      const type = usTime < themTime ? 'faster' : 'slower';
      const times = calculateTimes(usTime, themTime);
      const result: BenchmarkResult = {
        errorMsg: undefined,
        challenger: them.name,
        notes: them.notes,
        runCount: this.runCount * multiplier,
        fnName: this.name,
        time: themTime,
        us: usTime,
        type,
        times,
      };
      suite.addResult(result);
    });
  }

  /**
   * @returns time in ms
   */
  timeFn = (fn: BenchmarkFn, multiplier: number = 1): number => {
    // warm up imports, etc.
    fn();

    const totalRunCount = this.runCount * multiplier;

    // do the actual benchmark
    const start = performance.now();
    for (let i = 0; i < totalRunCount; i++) {
      fn();
    }
    const end = performance.now();
    return end - start;
  };
}
