import { Buffer } from '@craftzdog/react-native-buffer';
import {
  createSign,
  createVerify,
  generateKeyPair,
  createPrivateKey,
  createPublicKey,
  constants,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test, assertThrowsAsync } from '../util';

const SUITE = 'keys.sign/verify';

// RSA PEM keys for testing (2048-bit)
// Source: Node.js test fixtures
const rsaPrivateKeyPem = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7uLdVDMhouhsL
wgKi0O0+0AdGmJFU8a79RKlzrqUHCYJE1OAOUK6LFnNZ00zmFr2vN2M/FjVuV6DJ
1H1i1C0bFpJ/nOoFpPVBcI7VJ7bRbGJGjbE0hARYx9wBK9E0xtq6dW6RG3xOi0vF
WuVD1gy3c/4bTEZrBT3w0r/AyeBCh7JLfnZxlFLlQN5ZF/UH9Jb0uN0iZXfAIaJw
dBvLwmF7bRjYkxpJpFmL3V7J3rkEHCJE5ylZ3FjWLy+Fc1xXR3xVQm+rCJxXKWfL
MoH/aWFRL6YGxwzXJBFfQgcasKSNBzQKU1aGp4hKfFI2eHVUqcPn9rfS9o7eM2tO
DGLp3DxlAgMBAAECggEABu+5sjBLXAkyzNEHdLwMt/5I2Xo/rPJxuqGDKR3zrOrj
RxNHCuKLJyUyV7aQ0h9y4oE7SPBc0r/R7qx3L8Xg5oYR/UrNXJZKNnZl3DGxpVxD
qD8YfdZ0aKFYS6vU9DP7nDx3BGXN7GWFkDfZWpMHCNEOkBvB3LJ5PKZf9xqv3HxF
5x0W5fGJ5r3u3z/Av7vGQsQvQq1Np6xlKKj8FpnfWED3k0YXR1MXJFCmL+gBwq7s
0nT0dsMWbqNrD5vqvlN+2dZgqz5u8R1XUiYCcSJJ/yvUEPJTDfazKlhA5Z5V6k+j
r1lR5J5x6k8oEf4vFZ8sOl1V9nMPX3H7+b9F8R6xPQKBgQD5xIvVhP8qs2WKJKZV
6oPUCAQjR4qS3OgTKHQIjE0VLNQBfwF2B1ZWF1ZgEhNGChCAkzqDI8XEDqT3dN7t
N1qQ7vB7MfpGaEOy6H9M0jnZfGBYNxT+lPxPBSl0sK0ZnPzMvzLqR2vJvwYf/fG2
qHqDOvg2IjhXPpjYqlGxFmxfXwKBgQDA5z7WcXwN4EUj3frgD6e1gPVjJN9aDF7P
lveKPDpDXWm7E2n0lGxB0qxhP4QKxD5E1Ke1jkOTYe+0HTEAFF2Y/l6Z8TtXaH3x
TgX+0rMfbGxZ3h5sAQ5K6lCkfF8SBTK+Ug8c7C6LcLGKfPv0cP1wZsT6wJWAB2z3
VTINjBGKKwKBgBZ6dPqJwS3wq6JlnQ4HqfvWYMmYYItvfLF9VLsIJsBqQ7XVJQsR
qq6oKqM0dDPFb5FjGJMSL5T+S2UDUv3kXLl7w1p8VKVvmU7FxfFjJYCbECqTEBLD
PBl3C9K6K7NQtY1RfC0C0zw7lZNqZGVCE8UUL0qUqf9gFfQqvTgFRNXPAoGBALq5
6Q7X7mEX7p7mFwC6kFLqKFzWE0JYXd7x3PhCqE/P1f7P7TYM7vS8tZF3q1CLMf5w
OQJlZVbf1BNQZZ6RG5XmJNOFNqbFBm0m8P5LxVpmCZDfz4SRMOxJ8P7+qD7QXFJ6
DuJqCAXKNpVwJHJ9cQIYFj/XCJNQnJCJF5r9JvobAoGBAMx3LyCe1QEpD0LoLyXW
Y1OPRjJKMfRF2yQmVOMz7F9qiDbHXR3GkU0vXLbXqCfHEFTfAF+w9VDVYJFb+2P9
F3pCAhJzDM0gSNm2Y1EUKxgEcRz4bDJ3R3xMC1Zg5wqKmf4F0wOyj0bF1ZGF0qvz
hSDTHyxB1HjfbKrEYkf7qUQd
-----END PRIVATE KEY-----`;

const rsaPublicKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEAAAOCAQ8AMIIBCgKCAQEAu7i3VQzIaLobC8ICotDt
PtAHRpiRVPGu/USpc66lBwmCRNTgDlCuixZzWdNM5ha9rzdjPxY1blegydR9YtQt
GxaSf5zqBaT1QXCO1Se20WxiRo2xNIQEWMfcASvRNMbaunVukRt8TotLxVrlQ9YM
t3P+G0xGawU98NK/wMngQoeyS352cZRS5UDeWRf1B/SW9LjdImV3wCGicHQby8Jh
e20Y2JMaSaRZi91eyd65BBwiROcpWdxY1i8vhXNcV0d8VUJvqwicVylnyzKB/2lh
US+mBscM1yQRX0IHGrCkjQc0ClNWhqeISnxSNnh1VKnD5/a30vaO3jNrTgxi6dw8
ZQIDAQAB
-----END PUBLIC KEY-----`;

// EC P-256 keys for ECDSA testing (TODO: add EC sign/verify tests)
const _ecPrivateKeyPem = `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEICJxApEBg7MxZzh5JhtRSAj2rFnE0UYrj/swevFPCIGRoAcGBSuBBAAK
oUQDQgAEHtKhP2bJUHQoON4fB0ND/Z1ND6uQgfT7wBhMADWNxon36qP5Ypzb5z5x
nTHEi4WkLkxTqFsLYK5Gw/XPa+3hvw==
-----END EC PRIVATE KEY-----`;
void _ecPrivateKeyPem;

const _ecPublicKeyPem = `-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEHtKhP2bJUHQoON4fB0ND/Z1ND6uQgfT7
wBhMADWNxon36qP5Ypzb5z5xnTHEi4WkLkxTqFsLYK5Gw/XPa+3hvw==
-----END PUBLIC KEY-----`;
void _ecPublicKeyPem;

// Test data
const testData = 'Test message for signing';
const testDataBuffer = Buffer.from(testData);

// --- Basic Sign/Verify Tests ---

test(SUITE, 'createSign returns Sign instance', () => {
  const sign = createSign('SHA256');
  expect(typeof sign.update).to.equal('function');
  expect(typeof sign.sign).to.equal('function');
});

test(SUITE, 'createVerify returns Verify instance', () => {
  const verify = createVerify('SHA256');
  expect(typeof verify.update).to.equal('function');
  expect(typeof verify.verify).to.equal('function');
});

test(SUITE, 'RSA SHA256 sign and verify with PEM keys', () => {
  const sign = createSign('SHA256');
  sign.update(testData);
  const signature = sign.sign(rsaPrivateKeyPem);

  const verify = createVerify('SHA256');
  verify.update(testData);
  const isValid = verify.verify(rsaPublicKeyPem, signature);

  expect(isValid).to.equal(true);
});

test(SUITE, 'RSA SHA256 sign and verify with Buffer data', () => {
  const sign = createSign('SHA256');
  sign.update(testDataBuffer);
  const signature = sign.sign(rsaPrivateKeyPem);

  const verify = createVerify('SHA256');
  verify.update(testDataBuffer);
  const isValid = verify.verify(rsaPublicKeyPem, signature);

  expect(isValid).to.equal(true);
});

test(SUITE, 'RSA SHA256 multiple update calls', () => {
  const sign = createSign('SHA256');
  sign.update('Test ');
  sign.update('message ');
  sign.update('for signing');
  const signature = sign.sign(rsaPrivateKeyPem);

  const verify = createVerify('SHA256');
  verify.update('Test ');
  verify.update('message ');
  verify.update('for signing');
  const isValid = verify.verify(rsaPublicKeyPem, signature);

  expect(isValid).to.equal(true);
});

test(SUITE, 'RSA SHA256 chainable update calls', () => {
  const signature = createSign('SHA256')
    .update('Test ')
    .update('message ')
    .update('for signing')
    .sign(rsaPrivateKeyPem);

  const isValid = createVerify('SHA256')
    .update('Test ')
    .update('message ')
    .update('for signing')
    .verify(rsaPublicKeyPem, signature);

  expect(isValid).to.equal(true);
});

// --- Output Encoding Tests ---

test(SUITE, 'RSA sign with hex output encoding', () => {
  const sign = createSign('SHA256');
  sign.update(testData);
  const signature = sign.sign(rsaPrivateKeyPem, 'hex');

  expect(typeof signature).to.equal('string');
  expect(signature).to.match(/^[0-9a-f]+$/i);

  const verify = createVerify('SHA256');
  verify.update(testData);
  const isValid = verify.verify(rsaPublicKeyPem, signature, 'hex');

  expect(isValid).to.equal(true);
});

test(SUITE, 'RSA sign with base64 output encoding', () => {
  const sign = createSign('SHA256');
  sign.update(testData);
  const signature = sign.sign(rsaPrivateKeyPem, 'base64');

  expect(typeof signature).to.equal('string');
  expect(signature).to.match(/^[A-Za-z0-9+/]+=*$/);

  const verify = createVerify('SHA256');
  verify.update(testData);
  const isValid = verify.verify(rsaPublicKeyPem, signature, 'base64');

  expect(isValid).to.equal(true);
});

// --- Different Hash Algorithms ---

test(SUITE, 'RSA SHA1 sign and verify', () => {
  const sign = createSign('SHA1');
  sign.update(testData);
  const signature = sign.sign(rsaPrivateKeyPem);

  const verify = createVerify('SHA1');
  verify.update(testData);
  const isValid = verify.verify(rsaPublicKeyPem, signature);

  expect(isValid).to.equal(true);
});

test(SUITE, 'RSA SHA384 sign and verify', () => {
  const sign = createSign('SHA384');
  sign.update(testData);
  const signature = sign.sign(rsaPrivateKeyPem);

  const verify = createVerify('SHA384');
  verify.update(testData);
  const isValid = verify.verify(rsaPublicKeyPem, signature);

  expect(isValid).to.equal(true);
});

test(SUITE, 'RSA SHA512 sign and verify', () => {
  const sign = createSign('SHA512');
  sign.update(testData);
  const signature = sign.sign(rsaPrivateKeyPem);

  const verify = createVerify('SHA512');
  verify.update(testData);
  const isValid = verify.verify(rsaPublicKeyPem, signature);

  expect(isValid).to.equal(true);
});

// --- RSA-PSS Tests ---

test(SUITE, 'RSA-PSS with SHA256 and salt length', () => {
  const sign = createSign('SHA256');
  sign.update(testData);
  const signature = sign.sign({
    key: rsaPrivateKeyPem,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  });

  const verify = createVerify('SHA256');
  verify.update(testData);
  const isValid = verify.verify(
    {
      key: rsaPublicKeyPem,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32,
    },
    signature,
  );

  expect(isValid).to.equal(true);
});

test(SUITE, 'RSA-PSS with SHA256 and auto salt length', () => {
  const sign = createSign('SHA256');
  sign.update(testData);
  const signature = sign.sign({
    key: rsaPrivateKeyPem,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_AUTO,
  });

  const verify = createVerify('SHA256');
  verify.update(testData);
  const isValid = verify.verify(
    {
      key: rsaPublicKeyPem,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: constants.RSA_PSS_SALTLEN_AUTO,
    },
    signature,
  );

  expect(isValid).to.equal(true);
});

// --- KeyObject Tests ---

test(SUITE, 'Sign/Verify with KeyObject', () => {
  const privateKey = createPrivateKey(rsaPrivateKeyPem);
  const publicKey = createPublicKey(rsaPublicKeyPem);

  const sign = createSign('SHA256');
  sign.update(testData);
  const signature = sign.sign(privateKey);

  const verify = createVerify('SHA256');
  verify.update(testData);
  const isValid = verify.verify(publicKey, signature);

  expect(isValid).to.equal(true);
});

// --- Verification Failure Tests ---

test(SUITE, 'Verify fails with wrong data', () => {
  const sign = createSign('SHA256');
  sign.update(testData);
  const signature = sign.sign(rsaPrivateKeyPem);

  const verify = createVerify('SHA256');
  verify.update('Wrong data');
  const isValid = verify.verify(rsaPublicKeyPem, signature);

  expect(isValid).to.equal(false);
});

test(SUITE, 'Verify fails with tampered signature', () => {
  const sign = createSign('SHA256');
  sign.update(testData);
  const signature = sign.sign(rsaPrivateKeyPem);

  // Tamper with the signature
  const tamperedSig = Buffer.from(signature);
  tamperedSig[0] = (tamperedSig[0] ?? 0) ^ 0xff;

  const verify = createVerify('SHA256');
  verify.update(testData);
  const isValid = verify.verify(rsaPublicKeyPem, tamperedSig);

  expect(isValid).to.equal(false);
});

// --- Ed25519 Tests ---

test(SUITE, 'Ed25519 sign and verify', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'ed25519',
      {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      },
      (err, pubKey, privKey) => {
        if (err) reject(err);
        else
          resolve({
            privateKey: privKey as string,
            publicKey: pubKey as string,
          });
      },
    );
  });

  const sign = createSign('SHA512');
  sign.update(testData);
  const signature = sign.sign(privateKey);

  const verify = createVerify('SHA512');
  verify.update(testData);
  const isValid = verify.verify(publicKey, signature);

  expect(isValid).to.equal(true);
});

// --- ECDSA Tests ---

test(SUITE, 'ECDSA P-256 sign and verify with DER encoding', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'ec',
      {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      },
      (err, pubKey, privKey) => {
        if (err) reject(err);
        else
          resolve({
            privateKey: privKey as string,
            publicKey: pubKey as string,
          });
      },
    );
  });

  const sign = createSign('SHA256');
  sign.update(testData);
  const signature = sign.sign({
    key: privateKey,
    dsaEncoding: 'der',
  });

  const verify = createVerify('SHA256');
  verify.update(testData);
  const isValid = verify.verify(
    {
      key: publicKey,
      dsaEncoding: 'der',
    },
    signature,
  );

  expect(isValid).to.equal(true);
});

test(
  SUITE,
  'ECDSA P-256 sign and verify with IEEE-P1363 encoding',
  async () => {
    const { privateKey, publicKey } = await new Promise<{
      privateKey: string;
      publicKey: string;
    }>((resolve, reject) => {
      generateKeyPair(
        'ec',
        {
          namedCurve: 'P-256',
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        },
        (err, pubKey, privKey) => {
          if (err) reject(err);
          else
            resolve({
              privateKey: privKey as string,
              publicKey: pubKey as string,
            });
        },
      );
    });

    const sign = createSign('SHA256');
    sign.update(testData);
    const signature = sign.sign({
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    });

    // IEEE-P1363 signature for P-256 should be exactly 64 bytes (32 + 32)
    expect(signature.length).to.equal(64);

    const verify = createVerify('SHA256');
    verify.update(testData);
    const isValid = verify.verify(
      {
        key: publicKey,
        dsaEncoding: 'ieee-p1363',
      },
      signature,
    );

    expect(isValid).to.equal(true);
  },
);

// --- Error Cases ---

test(SUITE, 'Sign throws with null private key', async () => {
  const sign = createSign('SHA256');
  sign.update(testData);

  await assertThrowsAsync(async () => {
    sign.sign(null as unknown as string);
  }, 'Private key is required');
});

test(SUITE, 'Verify throws with null public key', async () => {
  const sign = createSign('SHA256');
  sign.update(testData);
  const signature = sign.sign(rsaPrivateKeyPem);

  const verify = createVerify('SHA256');
  verify.update(testData);

  await assertThrowsAsync(async () => {
    verify.verify(null as unknown as string, signature);
  }, 'Public key is required');
});

// --- generateKeyPair Integration Tests ---

test(SUITE, 'Sign/Verify with generateKeyPair RSA', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'rsa',
      {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      },
      (err, pubKey, privKey) => {
        if (err) reject(err);
        else
          resolve({
            privateKey: privKey as string,
            publicKey: pubKey as string,
          });
      },
    );
  });

  const sign = createSign('SHA256');
  sign.update(testData);
  const signature = sign.sign(privateKey);

  const verify = createVerify('SHA256');
  verify.update(testData);
  const isValid = verify.verify(publicKey, signature);

  expect(isValid).to.equal(true);
});
