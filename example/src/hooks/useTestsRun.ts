import { useCallback, useState } from 'react';
import type { TestSuites } from '../types/tests';
import type { Stats, SuiteResults, TestResult } from '../types/Results';

export const defaultStats = {
  start: new Date(),
  end: new Date(),
  duration: 0,
  suites: 0,
  tests: 0,
  passes: 0,
  pending: 0,
  failures: 0,
};

export const useTestsRun = (): [
  SuiteResults<TestResult>,
  (suites: TestSuites) => void,
  Stats | null,
] => {
  const [results, setResults] = useState<SuiteResults<TestResult>>({});
  const [stats, setStats] = useState<Stats | null>(null);

  const addResult = useCallback(
    (newResult: TestResult) => {
      setResults(prev => {
        if (!prev[newResult.suiteName]) {
          prev[newResult.suiteName] = { results: [] };
        }
        prev[newResult.suiteName]?.results.push(newResult);
        return { ...prev };
      });
    },
    [setResults],
  );

  const runTests = async (suites: TestSuites) => {
    setResults({});
    setStats(null);
    const finalStats = await run(addResult, suites);
    setStats(finalStats);
  };

  return [results, runTests, stats];
};

const run = async (
  addTestResult: (testResult: TestResult) => void,
  suites: TestSuites = {},
) => {
  const stats: Stats = { ...defaultStats };
  stats.start = new Date();

  const allTests = Object.entries(suites).flatMap(([suiteName, suite]) => {
    if (!suite.value) return [];
    stats.suites++;
    return Object.entries(suite.tests).map(async ([testName, test]) => {
      const testStart = performance.now();
      try {
        await test();
        const testDuration = performance.now() - testStart;
        stats.passes++;
        addTestResult({
          type: 'correct',
          description: testName,
          indentation: 0,
          suiteName,
          duration: testDuration,
        });
        console.log(
          `✅ Test "${suiteName} - ${testName}" passed in ${testDuration.toFixed(2)}ms!`,
        );
      } catch (e: unknown) {
        const err = e as Error;
        const testDuration = performance.now() - testStart;
        stats.failures++;
        addTestResult({
          type: 'incorrect',
          description: testName,
          indentation: 0,
          suiteName,
          errorMsg: err.message,
          duration: testDuration,
        });
        console.log(
          `❌ Test "${suiteName} - ${testName}" failed in ${testDuration.toFixed(2)}ms! ${err.message}`,
        );
      }
      stats.tests++;
    });
  });

  await Promise.all(allTests);

  stats.end = new Date();
  stats.duration = stats.end.valueOf() - stats.start.valueOf();
  return stats;
};
