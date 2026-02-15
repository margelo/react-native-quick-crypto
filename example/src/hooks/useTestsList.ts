import type { TestSuites } from '../types/tests';
import { TestsContext } from '../tests/util';
import { useSuiteList } from './useSuiteList';

import '../tests/argon2/argon2_tests';
import '../tests/blake3/blake3_tests';
import '../tests/certificate/certificate_tests';
import '../tests/cipher/chacha_tests';
import '../tests/cipher/cipher_tests';
import '../tests/cipher/cipherinfo_tests';
import '../tests/cipher/xchacha20_poly1305_tests';
import '../tests/cipher/xsalsa20_poly1305_tests';
import '../tests/cipher/xsalsa20_tests';
import '../tests/dh/dh_tests';
import '../tests/ecdh/ecdh_convertkey_tests';
import '../tests/ecdh/ecdh_tests';
import '../tests/hash/hash_tests';
import '../tests/hkdf/hkdf_tests';
import '../tests/hmac/hmac_tests';
import '../tests/jose/jose';
import '../tests/keys/create_keys';
import '../tests/keys/generate_key';
import '../tests/keys/generate_keypair';
import '../tests/keys/keyobject_from_tocryptokey_tests';
import '../tests/keys/public_cipher';
import '../tests/keys/sign_verify_error_queue';
import '../tests/keys/sign_verify_oneshot';
import '../tests/keys/sign_verify_streaming';
import '../tests/pbkdf2/pbkdf2_tests';
import '../tests/prime/prime_tests';
import '../tests/random/random_tests';
import '../tests/scrypt/scrypt_tests';
import '../tests/subtle/argon2_deriveBits';
import '../tests/subtle/deriveBits';
import '../tests/subtle/derive_key';
import '../tests/subtle/digest';
import '../tests/subtle/encrypt_decrypt';
import '../tests/subtle/generateKey';
import '../tests/subtle/import_export';
import '../tests/subtle/jwk_rfc7517_tests';
import '../tests/subtle/sign_verify';
import '../tests/subtle/supports';
import '../tests/subtle/getPublicKey';
import '../tests/subtle/wrap_unwrap';
import '../tests/utils/utils_tests';

export const useTestsList = (): [
  TestSuites,
  (description: string) => void,
  () => void,
  () => void,
] => useSuiteList(TestsContext);
