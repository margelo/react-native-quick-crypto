import { useCallback, useState } from 'react';
import type { BenchmarkSuite, Suites } from '../types/Suite';
import type { Stats, SuiteResults, BenchmarkResult } from '../types/Results';

const defaultStats = {
  start: new Date(),
  end: new Date(),
  duration: 0,
  suites: 0,
};

export const useBenchmarksRun = (): [SuiteResults<BenchmarkResult>, (suites: Suites<BenchmarkSuite>) => void] => {
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
    run(addResult, suites);
  };

  return [results, runBenchmarks];
};

const run = (
  addTestResult: (testResult: BenchmarkResult) => void,
  suites: Suites<BenchmarkSuite> = {}
) => {
  console.log(suites);

  Object.entries(suites).forEach(([suiteName, suite]) => {
    console.log(suiteName, suite);
  });
};
