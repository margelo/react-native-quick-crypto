import { useCallback, useState } from 'react';
import type { BenchmarkSuite, Suites } from '../types/Suite';
import type { SuiteResults, BenchmarkResult } from '../types/Results';

export const useBenchmarksRun = (runCount: number):
  [SuiteResults<BenchmarkResult>, (suites: Suites<BenchmarkSuite>) => void] => {
  const [results, setResults] = useState<SuiteResults<BenchmarkResult>>({});

  const addResult = useCallback(
    (newResult: BenchmarkResult) => {
      setResults((prev) => {
        if (!prev[newResult.suiteName]) {
          prev[newResult.suiteName] = { results: [] };
        }
        prev[newResult.suiteName]?.results.push(newResult);
        return { ...prev };
      });
    },
    [setResults]
  );

  const runBenchmarks = (suites: Suites<BenchmarkSuite>) => {
    setResults({});
    run(addResult, suites, runCount);
  };

  return [results, runBenchmarks];
};

const run = (
  addBenchmarkResult: (benchmarkResult: BenchmarkResult) => void,
  suites: Suites<BenchmarkSuite> = {},
  runCount: number
) => {
  Object.entries(suites).forEach(([suiteName, suite]) => {
    if (suite.value) {
      const res = suite.benchmarks.map((benchmark) => {
        if (!benchmark.them || !benchmark.us) {
          return;
        }
        const them = runBenchmark(benchmark.them as Function, runCount);
        const us = runBenchmark(benchmark.us as Function, runCount);
        addBenchmarkResult({
          indentation: 0,
          description: benchmark.name,
          suiteName,
          us,
          them,
          type: us < them ? 'faster' : 'slower',
        });
      });
    }
  });
};

const runBenchmark = (fn: Function, runCount: number): number => {
  // warm up imports, etc.
  fn();

  // do the actual benchmark
  const start = performance.now();
  for (let i = 0; i < runCount; i++) {
    fn();
  }
  const end = performance.now();
  return end - start;
};
