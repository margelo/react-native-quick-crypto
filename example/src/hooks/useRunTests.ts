import 'mocha';
import type * as MochaTypes from 'mocha';
import { useCallback, useState } from 'react';
import type { Suites } from '../types/TestSuite';
import type { Stats, SuiteResults, TestResult } from '../types/TestResults';
import { rootSuite } from '../testing/MochaRNAdapter';

const defaultStats = {
  start: new Date(),
  end: new Date(),
  duration: 0,
  suites: 0,
  tests: 0,
  passes: 0,
  pending: 0,
  failures: 0,
};

export const useRunTests = (): [SuiteResults, (suites: Suites) => void] => {
  const [results, setResults] = useState<SuiteResults>({});

  const addResult = useCallback(
    (newResult: TestResult) => {
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

  const runTests = (suites: Suites) => {
    setResults({});
    run(addResult, suites);
  };

  return [results, runTests];
};

const run = (
  addTestResult: (testResult: TestResult) => void,
  tests: Suites = {}
) => {
  const {
    EVENT_RUN_BEGIN,
    EVENT_RUN_END,
    EVENT_TEST_FAIL,
    EVENT_TEST_PASS,
    EVENT_TEST_PENDING,
    EVENT_TEST_END,
    EVENT_SUITE_BEGIN,
    EVENT_SUITE_END,
  } = Mocha.Runner.constants;

  let stats: Stats = { ...defaultStats };

  var runner = new Mocha.Runner(rootSuite) as MochaTypes.Runner;
  runner.stats = stats;

  // enable/disable tests based on checkbox value
  runner.suite.suites.map((s) => {
    const suiteName = s.title;
    if (!tests[suiteName]?.value) {
      // console.log(`skipping '${suiteName}' suite`);
      s.tests.map((t) => {
        try {
          t.skip();
        } catch (e) {} // do nothing w error
      });
    } else {
      // console.log(`will run '${suiteName}' suite`);
      s.tests.map((t) => {
        // @ts-expect-error - not sure why this is erroring
        t.reset();
      });
    }
  });

  let indents = -1;
  const indent = () => Array(indents).join('  ');
  runner
    .once(EVENT_RUN_BEGIN, () => {
      stats.start = new Date();
    })
    .on(EVENT_SUITE_BEGIN, (suite: MochaTypes.Suite) => {
      suite.root || stats.suites++;
      indents++;
    })
    .on(EVENT_SUITE_END, () => {
      indents--;
    })
    .on(EVENT_TEST_PASS, (test: MochaTypes.Runnable) => {
      const name = test.parent?.title || '';
      stats.passes++;
      addTestResult({
        indentation: indents,
        description: test.fullTitle(),
        suiteName: name,
        type: 'correct',
      });
      console.log(`${indent()}pass: ${test.fullTitle()}`);
    })
    .on(EVENT_TEST_FAIL, (test: MochaTypes.Runnable, err: Error) => {
      const name = test.parent?.title || '';
      stats.failures++;
      addTestResult({
        indentation: indents,
        description: test.fullTitle(),
        suiteName: name,
        type: 'incorrect',
        errorMsg: err.message,
      });
      console.log(
        `${indent()}fail: ${test.fullTitle()} - error: ${err.message}`
      );
    })
    .on(EVENT_TEST_PENDING, function () {
      stats.pending++;
    })
    .on(EVENT_TEST_END, function () {
      stats.tests++;
    })
    .once(EVENT_RUN_END, () => {
      stats.end = new Date();
      stats.duration = stats.end.valueOf() - stats.start.valueOf();
      console.log(JSON.stringify(runner.stats, null, 2));
    });

  runner.run();

  return () => {
    console.log('aborting');
    runner.abort();
  };
};
