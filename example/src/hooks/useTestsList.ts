import { useState, useCallback } from 'react';
import type { Suites, TestSuite } from '../types/Suite';
import { rootSuite } from '../testing/MochaRNAdapter';

// import '../testing/tests/pbkdf2Tests/pbkdf2Tests';
import '../testing/tests/random/random_tests';
// import '../testing/tests/HmacTests/HmacTests';
// import '../testing/tests/HashTests/HashTests';
// import '../testing/tests/CipherTests/CipherTestFirst';
// import '../testing/tests/CipherTests/CipherTestSecond';
// import '../testing/tests/CipherTests/PublicCipherTests';
// import '../testing/tests/CipherTests/test398';
// import '../testing/tests/CipherTests/generateKey';
// import '../testing/tests/CipherTests/GenerateKeyPairTests';
// import '../testing/tests/ConstantsTests/ConstantsTests';
// import '../testing/tests/SignTests/SignTests';
// import '../testing/tests/SmokeTests/bundlerTests';
// import '../testing/tests/webcryptoTests/deriveBits';
// import '../testing/tests/webcryptoTests/digest';
// import '../testing/tests/webcryptoTests/generateKey';
// import '../testing/tests/webcryptoTests/encrypt_decrypt';
// import '../testing/tests/webcryptoTests/import_export';
// import '../testing/tests/webcryptoTests/sign_verify';

export const useTestsList = (): [
  Suites<TestSuite>,
  (description: string) => void,
  () => void,
  () => void,
] => {
  const [suites, setSuites] = useState<Suites<TestSuite>>(getInitialSuites());

  const toggle = useCallback(
    (description: string) => {
      setSuites(tests => {
        tests[description]!.value = !tests[description]!.value;
        return tests;
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

const getInitialSuites = () => {
  const suites: Suites = {};

  // interrogate the loaded mocha suites/tests via a temporary runner
  const runner = new Mocha.Runner(rootSuite);
  runner.suite.suites.map(s => {
    suites[s.title] = { value: false, count: s.total() };
  });

  // return count-enhanced list and totals
  return suites;
};
