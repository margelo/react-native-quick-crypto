import { useState, useCallback } from 'react';
import type * as MochaTypes from 'mocha';
import type { Suites } from '../types/TestSuite';
import { rootSuite } from '../testing/MochaRNAdapter';

import '../testing/tests/pbkdf2Tests/pbkdf2Tests';
import '../testing/tests/RandomTests/randomTests';
import '../testing/tests/HmacTests/HmacTests';
import '../testing/tests/HashTests/HashTests';
import '../testing/tests/CipherTests/CipherDecipher';
import '../testing/tests/CipherTests/CipherivDecipheriv';
import '../testing/tests/CipherTests/PublicCipherTests';
import '../testing/tests/CipherTests/generateKey';
import '../testing/tests/CipherTests/GenerateKeyPairTests';
import '../testing/tests/ConstantsTests/ConstantsTests';
import '../testing/tests/SignTests/SignTests';
import '../testing/tests/webcryptoTests/deriveBits';
import '../testing/tests/webcryptoTests/digest';
import '../testing/tests/webcryptoTests/generateKey';
import '../testing/tests/webcryptoTests/encrypt_decrypt';
import '../testing/tests/webcryptoTests/import_export';
import '../testing/tests/webcryptoTests/sign_verify';
import '../testing/tests/SmokeTests/bundlerTests';
import '../testing/tests/issues/specific_issues';

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
    [setSuites],
  );

  const clearAll = useCallback(() => {
    setSuites((suites) => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      Object.entries(suites).forEach(([_, suite]) => {
        suite.value = false;
      });
      return { ...suites };
    });
  }, [setSuites]);

  const checkAll = useCallback(() => {
    setSuites((suites) => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      Object.entries(suites).forEach(([_, suite]) => {
        suite.value = true;
      });
      return { ...suites };
    });
  }, [setSuites]);

  return [suites, toggle, clearAll, checkAll];
};

const getInitialSuites = () => {
  const suites: Suites = {};

  // interrogate the loaded mocha suites/tests via a temporary runner
  const runner = new Mocha.Runner(rootSuite) as MochaTypes.Runner;
  runner.suite.suites.map((s) => {
    suites[s.title] = { value: false, count: s.total() };
  });

  // return count-enhanced list and totals
  return suites;
};
