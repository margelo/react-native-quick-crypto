import { useState, useCallback } from 'react';
import type { Suites, TestSuite } from '../types/suite';
import { TestsContext } from '../tests/util';

import '../tests/pbkdf2/pbkdf2_tests';
import '../tests/random/random_tests';
// import '../tests/HmacTests/HmacTests';
// import '../tests/HashTests/HashTests';
// import '../tests/CipherTests/CipherTestFirst';
// import '../tests/CipherTests/CipherTestSecond';
// import '../tests/CipherTests/PublicCipherTests';
// import '../tests/CipherTests/test398';
// import '../tests/CipherTests/generateKey';
// import '../tests/CipherTests/GenerateKeyPairTests';
// import '../tests/ConstantsTests/ConstantsTests';
// import '../tests/SignTests/SignTests';
// import '../tests/SmokeTests/bundlerTests';
// import '../tests/webcryptoTests/deriveBits';
// import '../tests/webcryptoTests/digest';
// import '../tests/webcryptoTests/generateKey';
// import '../tests/webcryptoTests/encrypt_decrypt';
// import '../tests/webcryptoTests/import_export';
// import '../tests/webcryptoTests/sign_verify';

export const useTestsList = (): [
  Suites<TestSuite>,
  (description: string) => void,
  () => void,
  () => void,
] => {
  const [suites, setSuites] = useState<Suites<TestSuite>>(TestsContext);

  const toggle = useCallback(
    (description: string) => {
      setSuites(suites => {
        suites[description]!.value = !suites[description]!.value;
        return suites;
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
