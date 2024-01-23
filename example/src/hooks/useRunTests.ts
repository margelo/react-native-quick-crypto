import 'mocha';
import type * as MochaTypes from 'mocha';
import { useCallback, useEffect, useState } from 'react';
import type { TestItemType } from '../navigators/children/Entry/TestItemType';
import type { RowItemType } from '../navigators/children/TestingScreen/RowItemType';
import { clearTests, rootSuite } from '../testing/MochaRNAdapter';

export const useRunTests = (
  tests: TestItemType[]
): [RowItemType[], () => void] => {
  const [results, setResults] = useState<RowItemType[]>([]);

  const addResult = useCallback(
    (newResult: RowItemType) => {
      setResults((prev) => [...prev, newResult]);
    },
    [setResults]
  );

  useEffect(
    () => {
      if (results.length > 0) return; // already running tests
      const testRegistrators: (() => void)[] = tests
        .filter((t) => t.value)
        .map((t) => t.registrator);
      run(addResult, testRegistrators);
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [results]
  );

  // this resets results to be empty, causing the useEffect to fire and run tests
  const runTests = () => {
    setResults([]);
  };

  // console.log({ results });
  return [results, runTests];
};

const run = (
  addTestResult: (testResult: RowItemType) => void,
  testRegistrators: Array<() => void> = []
) => {
  // console.log('setting up mocha');

  const {
    EVENT_RUN_BEGIN,
    EVENT_RUN_END,
    EVENT_TEST_FAIL,
    EVENT_TEST_PASS,
    EVENT_SUITE_BEGIN,
    EVENT_SUITE_END,
  } = Mocha.Runner.constants;

  clearTests();
  var runner = new Mocha.Runner(rootSuite) as MochaTypes.Runner;

  let indents = -1;
  const indent = () => Array(indents).join('  ');
  runner
    .once(EVENT_RUN_BEGIN, () => {})
    .on(EVENT_SUITE_BEGIN, (suite: MochaTypes.Suite) => {
      const name = suite.fullTitle();
      if (name !== '') {
        addTestResult({
          indentation: indents,
          description: name,
          key: Math.random().toString(),
          type: 'grouping',
        });
      }
      indents++;
    })
    .on(EVENT_SUITE_END, () => {
      indents--;
    })
    .on(EVENT_TEST_PASS, (test: MochaTypes.Runnable) => {
      addTestResult({
        indentation: indents,
        description: test.fullTitle(),
        key: Math.random().toString(),
        type: 'correct',
      });
      console.log(`${indent()}pass: ${test.fullTitle()}`);
    })
    .on(EVENT_TEST_FAIL, (test: MochaTypes.Runnable, err: Error) => {
      addTestResult({
        indentation: indents,
        description: test.fullTitle(),
        key: Math.random().toString(),
        type: 'incorrect',
        errorMsg: err.message,
      });
      console.log(
        `${indent()}fail: ${test.fullTitle()} - error: ${err.message}`
      );
    })
    .once(EVENT_RUN_END, () => {});

  testRegistrators.forEach((register) => {
    register();
  });
  runner.run();

  return () => {
    console.log('aborting');
    runner.abort();
  };
};
