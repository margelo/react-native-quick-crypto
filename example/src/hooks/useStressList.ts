import { useState, useCallback } from 'react';
import type { TestSuites } from '../types/tests';
import { StressContext } from '../stress/util';

import '../stress/ecdsa_sign_verify';

export const useStressList = (): [
  TestSuites,
  (description: string) => void,
  () => void,
  () => void,
] => {
  const [suites, setSuites] = useState<TestSuites>(StressContext);

  const toggle = useCallback(
    (description: string) => {
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
    },
    [setSuites],
  );

  const clearAll = useCallback(() => {
    setSuites(suites => {
      Object.values(suites).forEach(suite => {
        suite.value = false;
      });
      return { ...suites };
    });
  }, [setSuites]);

  const checkAll = useCallback(() => {
    setSuites(suites => {
      Object.values(suites).forEach(suite => {
        suite.value = true;
      });
      return { ...suites };
    });
  }, [setSuites]);

  return [suites, toggle, clearAll, checkAll];
};
