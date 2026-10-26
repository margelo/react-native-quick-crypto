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
  failedSuites: 0,
};

export const useTestsRun = (): [
  SuiteResults<TestResult>,
  (suites: TestSuites) => Promise<void>,
  Stats | null,
  boolean,
] => {
  const [results, setResults] = useState<SuiteResults<TestResult>>({});
  const [stats, setStats] = useState<Stats | null>(null);
  const [running, setRunning] = useState(false);

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

  const runTests = async (suites: TestSuites): Promise<void> => {
    if (running) return;

    setRunning(true);
    setResults({});
    setStats(null);
    try {
      const finalStats = await run(addResult, suites);
      setStats(finalStats);
    } finally {
      setRunning(false);
    }
  };

  return [results, runTests, stats, running];
};

const run = async (
  addTestResult: (testResult: TestResult) => void,
  suites: TestSuites = {},
): Promise<Stats> => {
  const stats: Stats = { ...defaultStats };
  const failedSuites = new Set<string>();
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
      } catch (error: unknown) {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        const testDuration = performance.now() - testStart;
        stats.failures++;
        failedSuites.add(suiteName);
        addTestResult({
          type: 'incorrect',
          description: testName,
          indentation: 0,
          suiteName,
          errorMsg: errorMessage,
          duration: testDuration,
        });
        console.log(
          `❌ Test "${suiteName} - ${testName}" failed in ${testDuration.toFixed(2)}ms! ${errorMessage}`,
        );
      }
      stats.tests++;
    });
  });

  await Promise.all(allTests);

  stats.end = new Date();
  stats.duration = stats.end.valueOf() - stats.start.valueOf();
  stats.failedSuites = failedSuites.size;
  return stats;
};
