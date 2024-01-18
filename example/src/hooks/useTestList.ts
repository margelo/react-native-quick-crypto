/* eslint-disable @typescript-eslint/no-shadow */
import { useState, useCallback } from 'react';
import type * as MochaTypes from 'mocha';
import type { TestItemType } from '../navigators/children/Entry/TestItemType';
import { TEST_LIST } from '../testing/TestList';
import { clearTests, rootSuite } from '../testing/MochaRNAdapter';

export const useTestList = (): [
  Array<TestItemType>,
  (index: number) => void,
  () => void,
  () => void,
  number
] => {
  const { testList, totalCount } = getTestList();
  const [tests, setTests] = useState<Array<TestItemType>>(testList);

  const toggle = useCallback(
    (index: number) => {
      setTests((tests) => {
        tests[index]!.value = !tests[index]!.value;
        return [...tests];
      });
    },
    [setTests]
  );

  const clearAll = useCallback(() => {
    setTests((tests) => {
      return tests.map((it) => {
        it.value = false;
        return it;
      });
    });
  }, [setTests]);

  const checkAll = useCallback(() => {
    setTests((tests) => {
      return tests.map((it) => {
        it.value = true;
        return it;
      });
    });
  }, [setTests]);

  return [tests, toggle, clearAll, checkAll, totalCount];
};

const getTestList = () => {
  let totalCount: number = 0;
  const testList = TEST_LIST.map((test) => {
    clearTests();
    test.registrator();

    const runner = new Mocha.Runner(rootSuite) as MochaTypes.Runner;
    let count = runner.suite.tests.length;
    runner.suite.suites.map((s) => {
      count += s.tests.length;
    });

    totalCount += count;
    return {
      ...test,
      count,
    };
  });
  clearTests();
  return { testList, totalCount };
};
