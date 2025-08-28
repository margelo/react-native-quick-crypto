import { useState, useCallback } from 'react';
import type { TestSuites } from '../types/tests';
import { TestsContext } from '../tests/util';

import '../tests/cipher/cipher_tests';
import '../tests/cipher/chacha_tests';
import '../tests/cipher/xsalsa20_tests';
import '../tests/ed25519/ed25519_tests';
import '../tests/ed25519/x25519_tests';
import '../tests/hash/hash_tests';
import '../tests/hmac/hmac_tests';
import '../tests/pbkdf2/pbkdf2_tests';
import '../tests/random/random_tests';

export const useTestsList = (): [
  TestSuites,
  (description: string) => void,
  () => void,
  () => void,
] => {
  const [suites, setSuites] = useState<TestSuites>(TestsContext);

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
