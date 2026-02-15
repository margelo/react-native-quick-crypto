import { useState, useCallback } from 'react';
import type { TestSuites } from '../types/tests';

export const useSuiteList = (
  initialContext: TestSuites,
): [TestSuites, (description: string) => void, () => void, () => void] => {
  const [suites, setSuites] = useState<TestSuites>(initialContext);

  const toggle = useCallback((description: string) => {
    setSuites(prevSuites => {
      const newSuites = { ...prevSuites };
      if (newSuites[description]) {
        newSuites[description] = {
          ...newSuites[description],
          value: !newSuites[description].value,
        };
      }
      return newSuites;
    });
  }, []);

  const clearAll = useCallback(() => {
    setSuites(
      prevSuites =>
        Object.fromEntries(
          Object.entries(prevSuites).map(([key, suite]) => [
            key,
            { ...suite, value: false },
          ]),
        ) as TestSuites,
    );
  }, []);

  const checkAll = useCallback(() => {
    setSuites(
      prevSuites =>
        Object.fromEntries(
          Object.entries(prevSuites).map(([key, suite]) => [
            key,
            { ...suite, value: true },
          ]),
        ) as TestSuites,
    );
  }, []);

  return [suites, toggle, clearAll, checkAll];
};
