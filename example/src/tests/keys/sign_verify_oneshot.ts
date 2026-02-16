import {
  Buffer,
  sign,
  verify,
  generateKeyPair,
  createPrivateKey,
  createPublicKey,
  constants,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';
import { rsaPrivateKeyPem, rsaPublicKeyPem } from './fixtures';

const SUITE = 'keys.sign/verify';

const testData = 'Test message for signing';
const testDataBuffer = Buffer.from(testData);

// --- Basic One-Shot Sign/Verify Tests ---

test(SUITE, 'sign and verify with RSA SHA256', () => {
  const signature = sign('SHA256', testData, rsaPrivateKeyPem);
  expect(Buffer.isBuffer(signature)).to.equal(true);

  const isValid = verify('SHA256', testData, rsaPublicKeyPem, signature);
  expect(isValid).to.equal(true);
});

test(SUITE, 'sign and verify with Buffer data', () => {
  const signature = sign('SHA256', testDataBuffer, rsaPrivateKeyPem);
  const isValid = verify('SHA256', testDataBuffer, rsaPublicKeyPem, signature);
  expect(isValid).to.equal(true);
});

test(SUITE, 'sign and verify with null algorithm (key-dependent)', async () => {
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

  const signature = sign(null, testData, privateKey);
  const isValid = verify(null, testData, publicKey, signature);
  expect(isValid).to.equal(true);
});

// --- Different Hash Algorithms ---

test(SUITE, 'sign and verify with SHA1', () => {
  const signature = sign('SHA1', testData, rsaPrivateKeyPem);
  const isValid = verify('SHA1', testData, rsaPublicKeyPem, signature);
  expect(isValid).to.equal(true);
});

test(SUITE, 'sign and verify with SHA384', () => {
  const signature = sign('SHA384', testData, rsaPrivateKeyPem);
  const isValid = verify('SHA384', testData, rsaPublicKeyPem, signature);
  expect(isValid).to.equal(true);
});

test(SUITE, 'sign and verify with SHA512', () => {
  const signature = sign('SHA512', testData, rsaPrivateKeyPem);
  const isValid = verify('SHA512', testData, rsaPublicKeyPem, signature);
  expect(isValid).to.equal(true);
});

// --- KeyObject Tests ---

test(SUITE, 'sign and verify with KeyObject', () => {
  const privateKey = createPrivateKey(rsaPrivateKeyPem);
  const publicKey = createPublicKey(rsaPublicKeyPem);

  const signature = sign('SHA256', testData, privateKey);
  const isValid = verify('SHA256', testData, publicKey, signature);
  expect(isValid).to.equal(true);
});

// --- RSA-PSS Tests ---

test(SUITE, 'RSA-PSS with padding and salt length options', () => {
  const signature = sign('SHA256', testData, {
    key: rsaPrivateKeyPem,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  });

  const isValid = verify(
    'SHA256',
    testData,
    {
      key: rsaPublicKeyPem,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32,
    },
    signature,
  );

  expect(isValid).to.equal(true);
});

// --- ECDSA Tests ---

test(SUITE, 'ECDSA P-256 with DER encoding', async () => {
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

  const signature = sign('SHA256', testData, {
    key: privateKey,
    dsaEncoding: 'der',
  });

  const isValid = verify(
    'SHA256',
    testData,
    {
      key: publicKey,
      dsaEncoding: 'der',
    },
    signature,
  );

  expect(isValid).to.equal(true);
});

test(SUITE, 'ECDSA P-256 with IEEE-P1363 encoding', async () => {
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

  const signature = sign('SHA256', testData, {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });

  expect(signature.length).to.equal(64);

  const isValid = verify(
    'SHA256',
    testData,
    {
      key: publicKey,
      dsaEncoding: 'ieee-p1363',
    },
    signature,
  );

  expect(isValid).to.equal(true);
});

test(SUITE, 'ECDSA P-384 with IEEE-P1363 encoding', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'ec',
      {
        namedCurve: 'P-384',
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

  const signature = sign('SHA384', testData, {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });

  expect(signature.length).to.equal(96);

  const isValid = verify(
    'SHA384',
    testData,
    {
      key: publicKey,
      dsaEncoding: 'ieee-p1363',
    },
    signature,
  );

  expect(isValid).to.equal(true);
});

test(SUITE, 'ECDSA P-521 with IEEE-P1363 encoding', async () => {
  const { privateKey, publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'ec',
      {
        namedCurve: 'P-521',
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

  const signature = sign('SHA512', testData, {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });

  expect(signature.length).to.equal(132);

  const isValid = verify(
    'SHA512',
    testData,
    {
      key: publicKey,
      dsaEncoding: 'ieee-p1363',
    },
    signature,
  );

  expect(isValid).to.equal(true);
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

  // Ed25519 uses its own internal hashing, so algorithm should be null
  const signature = sign(null, testData, privateKey);
  const isValid = verify(null, testData, publicKey, signature);
  expect(isValid).to.equal(true);
});

// --- Callback API Tests ---

test(SUITE, 'sign with callback', async () => {
  await new Promise<void>(resolve => {
    sign(
      'SHA256',
      testData,
      rsaPrivateKeyPem,
      (err: Error | null, signature?: Buffer) => {
        expect(err).to.equal(null);
        expect(Buffer.isBuffer(signature)).to.equal(true);

        const isValid = verify('SHA256', testData, rsaPublicKeyPem, signature!);
        expect(isValid).to.equal(true);
        resolve();
      },
    );
  });
});

test(SUITE, 'verify with callback', async () => {
  const signature = sign('SHA256', testData, rsaPrivateKeyPem);

  await new Promise<void>(resolve => {
    verify(
      'SHA256',
      testData,
      rsaPublicKeyPem,
      signature!,
      (err: Error | null, result?: boolean) => {
        expect(err).to.equal(null);
        expect(result).to.equal(true);
        resolve();
      },
    );
  });
});

// --- Verification Failure Tests ---

test(SUITE, 'verify fails with wrong data', () => {
  const signature = sign('SHA256', testData, rsaPrivateKeyPem);
  const isValid = verify('SHA256', 'Wrong data', rsaPublicKeyPem, signature);
  expect(isValid).to.equal(false);
});

test(SUITE, 'verify fails with tampered signature', () => {
  const signature = sign('SHA256', testData, rsaPrivateKeyPem);

  const tamperedSig = Buffer.from(signature);
  tamperedSig[0] = (tamperedSig[0] ?? 0) ^ 0xff;

  const isValid = verify('SHA256', testData, rsaPublicKeyPem, tamperedSig);
  expect(isValid).to.equal(false);
});

// --- Error Cases ---

test(SUITE, 'sign throws with null key', () => {
  expect(() => {
    sign('SHA256', testData, null as unknown as string);
  }).to.throw('Private key is required');
});

test(SUITE, 'verify throws with null key', () => {
  const signature = sign('SHA256', testData, rsaPrivateKeyPem);
  expect(() => {
    verify('SHA256', testData, null as unknown as string, signature);
  }).to.throw('Key is required');
});

// --- Callback Error Handling Tests ---

test(SUITE, 'sign callback receives error for invalid key', async () => {
  await new Promise<void>(resolve => {
    sign(
      'SHA256',
      testData,
      null as unknown as string,
      (err: Error | null, signature?: Buffer) => {
        expect(err).to.be.instanceOf(Error);
        expect(err?.message).to.equal('Private key is required');
        expect(signature).to.equal(undefined);
        resolve();
      },
    );
  });
});

test(SUITE, 'verify callback receives error for invalid key', async () => {
  const validSignature = sign('SHA256', testData, rsaPrivateKeyPem);
  await new Promise<void>(resolve => {
    verify(
      'SHA256',
      testData,
      null as unknown as string,
      validSignature,
      (err: Error | null, result?: boolean) => {
        expect(err).to.be.instanceOf(Error);
        expect(err?.message).to.equal('Key is required');
        expect(result).to.equal(undefined);
        resolve();
      },
    );
  });
});
