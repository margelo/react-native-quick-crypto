import { test } from '../util';
import { Certificate, Buffer } from 'react-native-quick-crypto';
import { assert } from 'chai';

const SUITE = 'certificate';

// Node.js test fixture: 2048-bit RSA SPKAC with challenge "this-is-a-challenge"
const validSpkac =
  'MIICUzCCATswggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC33FiI' +
  'iiexwLe/P8DZx5HsqFlmUO7/lvJ7necJVNwqdZ3ax5jpQB0p6uxfqeOvzcN3' +
  'k5V7UFb/Am+nkSNZMAZhsWzCU2Z4Pjh50QYz3f0Hour7/yIGStOLyYY3hgLK' +
  '2K8TbhgjQPhdkw9+QtKlpvbL8fLgONAoGrVOFnRQGcr70iFffsm79mgZhKVM' +
  'gYiHPJqJgGHvCtkGg9zMgS7p63+Q3ZWedtFS2RhMX3uCBy/mH6EOlRCNBbRm' +
  'A4xxNzyf5GQaki3T+Iz9tOMjdPP+CwV2LqEdylmBuik8vrfTb3qIHLKKBAI8l' +
  'XN26wWtA3kN4L7NP+cbKlCRlqctvhmylLH1AgMBAAEWE3RoaXMtaXMtYS1jaG' +
  'FsbGVuZ2UwDQYJKoZIhvcNAQEEBQADggEBAIozmeW1kfDfAVwRQKileZGLRGCD' +
  '7AjdHLYEe16xTBPve8Af1bDOyuWsAm4qQLYA4FAFROiKeGqxCtIErEvm87/09' +
  'tCfF1My/1Uj+INjAk39DK9J9alLlTsrwSgd1lb3YlXY7TyitCmh7iXLo4pVhA' +
  '2chNA3njiMq3CUpSvGbpzrESL2dv97lv590gUD988wkTDVyYsf0T8+X0Kww3Ag' +
  'PWGji+2f2i5/jTfD/s1lK1nqi7ZxFm0pGZoy1MJ51SCEy7Y82ajroI+5786nC0' +
  '2mo9ak7samca4YDZOoxN4d3tax4B/HDF5dqJSm1/31xYLDTfujCM5FkSjRc4m6' +
  'hnriEkc=';

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

test(SUITE, 'exportChallenge returns correct challenge string', () => {
  const result = Certificate.exportChallenge(validSpkac);
  assert.isTrue(Buffer.isBuffer(result));
  assert.strictEqual(result.toString('utf8'), 'this-is-a-challenge');
});

test(SUITE, 'exportChallenge returns empty buffer for invalid SPKAC', () => {
  const result = Certificate.exportChallenge(invalidSpkac);
  assert.isTrue(Buffer.isBuffer(result));
  assert.strictEqual(result.length, 0);
});
