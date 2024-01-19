import { useCallback, useEffect, useState } from 'react';
import type { TestItemType } from '../navigators/children/Entry/TestItemType';
import type { RowItemType } from '../navigators/children/TestingScreen/RowItemType';
import { testLib } from '../testing/MochaSetup';

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
      testLib(addResult, testRegistrators);
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [results]
  );

  const runTests = () => {
    setResults([]);
  };

  console.log({ results });
  return [results, runTests];
};
