import { test } from '../util';
import { Certificate, Buffer } from 'react-native-quick-crypto';
import { assert } from 'chai';

const SUITE = 'certificate';

// Known valid SPKAC (Netscape Signed Public Key and Challenge)
// Generated with: openssl spkac -key test.pem -challenge test
const validSpkac =
  'MIIBXjCByDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA3V' +
  'OalmRSaIBk2fVEKEECNBbOJMFCMHBOBYhBjqRLNeGq8GOWQ6qn' +
  'FJycJgbYxOWL/4y7FuyFdEiRm3lMiDl0FR2WzhqFDsT7LMfMaV' +
  'Bv39JMmPOfUoqHaEYAN2Bvw9bMT0DHXpcFVGkDHFnYPFvKfBxKx' +
  'mCYSiEkGrgK7yDiwl2kCAwEAARYEbm9uZTANBgkqhkiG9w0BAQQ' +
  'FAAOBgQAwxfKEBHCCfQ4UMsBd0zmrU+ISi2VHDhj9VKZea2Sy3p' +
  'A/wsjKQqZ4vX0LkbFezJR0RA+Nz1dm31GrKHloXYgqfUTfNOlBO' +
  'UQOd2mMa8c4qRMGBfY+GSZVY34TFNJrQrcSHTmkOy3Hm6dMR0X' +
  'qzRA/vGAZ0N0N2g+JFAFKYCBbQ==';

const invalidSpkac = 'not-a-valid-spkac';

test(SUITE, 'verifySpkac returns true for valid SPKAC', () => {
  const result = Certificate.verifySpkac(validSpkac);
  assert.isTrue(result);
});

test(SUITE, 'verifySpkac returns false for invalid SPKAC', () => {
  const result = Certificate.verifySpkac(invalidSpkac);
  assert.isFalse(result);
});

test(SUITE, 'verifySpkac accepts Buffer input', () => {
  const buf = Buffer.from(invalidSpkac);
  const result = Certificate.verifySpkac(buf);
  assert.isFalse(result);
});

test(SUITE, 'exportPublicKey returns Buffer', () => {
  const result = Certificate.exportPublicKey(validSpkac);
  assert.isOk(result);
  assert.isTrue(Buffer.isBuffer(result));
});

test(SUITE, 'exportPublicKey returns empty buffer for invalid SPKAC', () => {
  const result = Certificate.exportPublicKey(invalidSpkac);
  assert.isTrue(Buffer.isBuffer(result));
  assert.strictEqual(result.length, 0);
});

test(SUITE, 'exportChallenge returns Buffer', () => {
  const result = Certificate.exportChallenge(validSpkac);
  assert.isOk(result);
  assert.isTrue(Buffer.isBuffer(result));
});

test(SUITE, 'exportChallenge returns empty buffer for invalid SPKAC', () => {
  const result = Certificate.exportChallenge(invalidSpkac);
  assert.isTrue(Buffer.isBuffer(result));
  assert.strictEqual(result.length, 0);
});
