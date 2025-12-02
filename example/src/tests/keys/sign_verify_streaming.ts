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
import { rsaPrivateKeyPem, rsaPublicKeyPem } from './fixtures';

const SUITE = 'keys.sign/verify';

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
