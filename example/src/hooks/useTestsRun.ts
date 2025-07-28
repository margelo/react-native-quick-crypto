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
] => {
  const [results, setResults] = useState<SuiteResults<TestResult>>({});

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

  const runTests = (suites: TestSuites) => {
    setResults({});
    run(addResult, suites);
  };

  return [results, runTests];
};

const run = (
  addTestResult: (testResult: TestResult) => void,
  suites: TestSuites = {},
) => {
  const stats: Stats = { ...defaultStats };
  stats.start = new Date();

  Object.entries(suites).map(([suiteName, suite]) => {
    stats.suites++;

    Object.entries(suite.tests).map(async ([testName, test]) => {
      if (!suite.value) return;
      try {
        await test();
        stats.passes++;
        addTestResult({
          type: 'correct',
          description: testName,
          indentation: 0,
          suiteName,
        });
        console.log(`✅ Test "${suiteName} - ${testName}" passed!`);
      } catch (e: unknown) {
        const err = e as Error;
        stats.failures++;
        addTestResult({
          type: 'incorrect',
          description: testName,
          indentation: 0,
          suiteName,
          errorMsg: err.message,
        });
        console.log(
          `❌ Test "${suiteName} - ${testName}" failed! ${err.message}`,
        );
      }
      stats.tests++;
    });
  });

  stats.end = new Date();
  stats.duration = stats.end.valueOf() - stats.start.valueOf();
  return stats;
};
