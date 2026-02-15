/**
 * Regression test for GitHub issue #118:
 * "Failed to read private key" after calling other crypto operations.
 *
 * The original bug was caused by OpenSSL error queue pollution — calling
 * operations like pbkdf2Sync before sign() would leave stale errors in the
 * per-thread error queue, causing subsequent key parsing to fail.
 */

import {
  Buffer,
  sign,
  verify,
  createHash,
  createHmac,
  pbkdf2Sync,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  generateKeyPairSync,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';
import { rsaPrivateKeyPem, rsaPublicKeyPem } from './fixtures';

const SUITE = 'keys.sign/verify';

const testData = Buffer.from('test data for issue 118');

const ITERATIONS = 10;

test(SUITE, 'sign after pbkdf2Sync (repeated)', () => {
  for (let i = 0; i < ITERATIONS; i++) {
    pbkdf2Sync('password', 'salt', 1000, 32, 'SHA-256');
    const sig = sign('SHA256', testData, rsaPrivateKeyPem);
    const valid = verify('SHA256', testData, rsaPublicKeyPem, sig);
    expect(valid).to.equal(true, `iteration ${i} failed`);
  }
});

test(SUITE, 'sign after createHash (repeated)', () => {
  for (let i = 0; i < ITERATIONS; i++) {
    createHash('sha256').update('some data').digest();
    const sig = sign('SHA256', testData, rsaPrivateKeyPem);
    const valid = verify('SHA256', testData, rsaPublicKeyPem, sig);
    expect(valid).to.equal(true, `iteration ${i} failed`);
  }
});

test(SUITE, 'sign after createHmac (repeated)', () => {
  for (let i = 0; i < ITERATIONS; i++) {
    createHmac('sha256', 'secret').update('some data').digest();
    const sig = sign('SHA256', testData, rsaPrivateKeyPem);
    const valid = verify('SHA256', testData, rsaPublicKeyPem, sig);
    expect(valid).to.equal(true, `iteration ${i} failed`);
  }
});

test(SUITE, 'sign after AES cipher/decipher (repeated)', () => {
  const key = Buffer.alloc(32, 0xab);
  const iv = Buffer.alloc(16, 0xcd);
  const plaintext = Buffer.from('hello world');

  for (let i = 0; i < ITERATIONS; i++) {
    const cipher = createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);

    const decipher = createDecipheriv('aes-256-cbc', key, iv);
    Buffer.concat([decipher.update(encrypted), decipher.final()]);

    const sig = sign('SHA256', testData, rsaPrivateKeyPem);
    const valid = verify('SHA256', testData, rsaPublicKeyPem, sig);
    expect(valid).to.equal(true, `iteration ${i} failed`);
  }
});

test(SUITE, 'sign after mixed crypto operations (repeated)', () => {
  for (let i = 0; i < ITERATIONS; i++) {
    pbkdf2Sync('password', 'salt', 100, 32, 'SHA-512');
    createHash('sha512').update(randomBytes(64)).digest();
    createHmac('sha384', 'key').update('data').digest();
    pbkdf2Sync('pass2', 'salt2', 100, 64, 'SHA-384');

    const sig = sign('SHA256', testData, rsaPrivateKeyPem);
    const valid = verify('SHA256', testData, rsaPublicKeyPem, sig);
    expect(valid).to.equal(true, `iteration ${i} failed`);
  }
});

test(SUITE, 'Ed25519 sign after mixed crypto operations', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  for (let i = 0; i < ITERATIONS; i++) {
    pbkdf2Sync('password', 'salt', 100, 32, 'SHA-256');
    createHash('sha256').update('noise').digest();

    const sig = sign(null, testData, privateKey as string);
    const valid = verify(null, testData, publicKey as string, sig);
    expect(valid).to.equal(true, `iteration ${i} failed`);
  }
});

test(SUITE, 'ECDSA sign after mixed crypto operations', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  for (let i = 0; i < ITERATIONS; i++) {
    pbkdf2Sync('password', 'salt', 100, 32, 'SHA-256');
    createHash('sha384').update('noise').digest();

    const sig = sign('SHA256', testData, privateKey as string);
    const valid = verify('SHA256', testData, publicKey as string, sig);
    expect(valid).to.equal(true, `iteration ${i} failed`);
  }
});
