import { useState, useCallback } from 'react';
import type { TestSuites } from '../types/tests';
import { TestsContext } from '../tests/util';

import '../tests/blake3/blake3_tests';
import '../tests/cipher/cipher_tests';
import '../tests/cipher/chacha_tests';
import '../tests/cipher/xsalsa20_tests';
import '../tests/cfrg/ed25519_tests';
import '../tests/cfrg/x25519_tests';
import '../tests/constants/constants_tests';
import '../tests/hash/hash_tests';
import '../tests/hmac/hmac_tests';
import '../tests/jose/jose';
import '../tests/keys/create_keys';
import '../tests/keys/generate_key';
import '../tests/keys/generate_keypair';
import '../tests/keys/public_cipher';
import '../tests/keys/sign_verify_streaming';
import '../tests/pbkdf2/pbkdf2_tests';
import '../tests/random/random_tests';
import '../tests/subtle/deriveBits';
import '../tests/subtle/digest';
import '../tests/subtle/encrypt_decrypt';
import '../tests/subtle/generateKey';
import '../tests/subtle/import_export';
import '../tests/subtle/jwk_rfc7517_tests';
import '../tests/subtle/sign_verify';
import '../tests/subtle/x25519_x448';
import '../tests/subtle/wrap_unwrap';
import '../tests/subtle/derive_key';

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
