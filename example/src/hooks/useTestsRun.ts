import { useCallback, useState } from 'react';
import type { Suites } from '../types/suite';
import type { TestSuite } from '../types/tests';
import type { Stats, SuiteResults, TestResult } from '../types/results';

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
  (suites: Suites<TestSuite>) => void,
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

  const runTests = (suites: Suites<TestSuite>) => {
    setResults({});
    run(addResult, suites);
  };

  return [results, runTests];
};

const run = (
  addTestResult: (testResult: TestResult) => void,
  suites: Suites<TestSuite> = {},
) => {
  const stats: Stats = { ...defaultStats };
  stats.start = new Date();

  Object.entries(suites).map(([suiteName, suite]) => {
    stats.suites++;

    Object.entries(suite.tests).map(([testName, test]) => {
      if (!suite.value) return;
      try {
        test();
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

// const run = (
//   addTestResult: (testResult: TestResult) => void,
//   tests: Suites<TestSuite> = {},
// ) => {
//   const {
//     EVENT_RUN_BEGIN,
//     EVENT_RUN_END,
//     EVENT_TEST_FAIL,
//     EVENT_TEST_PASS,
//     EVENT_TEST_PENDING,
//     EVENT_TEST_END,
//     EVENT_SUITE_BEGIN,
//     EVENT_SUITE_END,
//   } = Mocha.Runner.constants;

//   const stats: Stats = { ...defaultStats };

//   const runner = new Mocha.Runner(rootSuite);
//   runner.stats = stats;

//   // enable/disable tests based on checkbox value
//   runner.suite.suites.map(s => {
//     const suiteName = s.title;
//     if (!tests[suiteName]?.value) {
//       // console.log(`skipping '${suiteName}' suite`);
//       s.tests.map(t => {
//         t.skip();
//       });
//     } else {
//       // console.log(`will run '${suiteName}' suite`);
//       s.tests.map(t => {
//         // @ts-expect-error - not sure why this is erroring
//         t.reset();
//       });
//     }
//   });

//   let indents = -1;
//   const indent = () => Array(indents).join('  ');
//   runner
//     .once(EVENT_RUN_BEGIN, () => {
//       stats.start = new Date();
//     })
//     .on(EVENT_SUITE_BEGIN, (suite: MochaTypes.Suite) => {
//       if (!suite.root) stats.suites++;
//       indents++;
//     })
//     .on(EVENT_SUITE_END, () => {
//       indents--;
//     })
//     .on(EVENT_TEST_PASS, (test: MochaTypes.Runnable) => {
//       const name = test.parent?.title || '';
//       stats.passes++;
//       addTestResult({
//         indentation: indents,
//         description: test.title,
//         suiteName: name,
//         type: 'correct',
//       });
//       console.log(`${indent()}pass: ${test.title}`);
//     })
//     .on(EVENT_TEST_FAIL, (test: MochaTypes.Runnable, err: Error) => {
//       const name = test.parent?.title || '';
//       stats.failures++;
//       addTestResult({
//         indentation: indents,
//         description: test.title,
//         suiteName: name,
//         type: 'incorrect',
//         errorMsg: err.message,
//       });
//       console.log(`${indent()}fail: ${test.title} - error: ${err.message}`);
//     })
//     .on(EVENT_TEST_PENDING, function () {
//       stats.pending++;
//     })
//     .on(EVENT_TEST_END, function () {
//       stats.tests++;
//     })
//     .once(EVENT_RUN_END, () => {
//       stats.end = new Date();
//       stats.duration = stats.end.valueOf() - stats.start.valueOf();
//       console.log(JSON.stringify(runner.stats, null, 2));
//     });

//   runner.run();

//   return () => {
//     console.log('aborting');
//     runner.abort();
//   };
// };
