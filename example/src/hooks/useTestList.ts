/* eslint-disable @typescript-eslint/no-shadow */
import { useState, useCallback } from 'react';
import type * as MochaTypes from 'mocha';
import type { Suites } from '../types/TestSuite';
import { rootSuite } from '../testing/MochaRNAdapter';

import '../testing/Tests/pbkdf2Tests/pbkdf2Tests';
import '../testing/Tests/RandomTests/randomTests';
import '../testing/Tests/HmacTests/HmacTests';
import '../testing/Tests/HashTests/HashTests';
import '../testing/Tests/CipherTests/CipherTestFirst';
import '../testing/Tests/CipherTests/CipherTestSecond';
import '../testing/Tests/CipherTests/PublicCipherTests';
import '../testing/Tests/CipherTests/GenerateKeyPairTests';
import '../testing/Tests/ConstantsTests/ConstantsTests';
import '../testing/Tests/SignTests/SignTests';
import '../testing/Tests/SmokeTests/bundlerTests';
import '../testing/Tests/webcryptoTests/deriveBits';
import '../testing/Tests/webcryptoTests/digest';
import '../testing/Tests/webcryptoTests/generateKey';
import '../testing/Tests/webcryptoTests/import_export';
import '../testing/Tests/webcryptoTests/sign_verify';

export const useTestList = (): [
  Suites,
  (description: string) => void,
  () => void,
  () => void,
] => {
  const [suites, setSuites] = useState<Suites>(getInitialSuites());

  const toggle = useCallback(
    (description: string) => {
      setSuites((tests) => {
        tests[description]!.value = !tests[description]!.value;
        return tests;
      });
    },
    [setSuites]
  );

  const clearAll = useCallback(() => {
    setSuites((suites) => {
      Object.entries(suites).forEach(([_, suite]) => {
        suite.value = false;
      });
      return { ...suites };
    });
  }, [setSuites]);

  const checkAll = useCallback(() => {
    setSuites((suites) => {
      Object.entries(suites).forEach(([_, suite]) => {
        suite.value = true;
      });
      return { ...suites };
    });
  }, [setSuites]);

  return [suites, toggle, clearAll, checkAll];
};

const getInitialSuites = () => {
  let suites: Suites = {};

  // interrogate the loaded mocha suites/tests via a temporary runner
  const runner = new Mocha.Runner(rootSuite) as MochaTypes.Runner;
  runner.suite.suites.map((s) => {
    suites[s.title] = { value: false, count: s.total() };
  });

  // return count-enhanced list and totals
  return suites;
};
