import {
  Buffer,
  normalizeHashName,
  subtle,
  isCryptoKeyPair,
  CryptoKey,
  ab2str,
  Ed,
  randomBytes,
} from 'react-native-quick-crypto';
import type {
  CryptoKeyPair,
  WebCryptoKeyPair,
} from 'react-native-quick-crypto';
import { test } from '../util';
import { expect } from 'chai';

const encoder = new TextEncoder();

const SUITE = 'subtle.sign/verify';

const testData = encoder.encode('Test message for WebCrypto signing');
const emptyData = new Uint8Array(0);

async function generateKeyPairChecked(
  ...args: Parameters<typeof subtle.generateKey>
): Promise<WebCryptoKeyPair> {
  const result = await subtle.generateKey(...args);
  if (!isCryptoKeyPair(result)) throw new Error('Expected key pair');
  return result as WebCryptoKeyPair;
}

async function generateSymmetricKeyChecked(
  ...args: Parameters<typeof subtle.generateKey>
): Promise<CryptoKey> {
  const result = await subtle.generateKey(...args);
  if (isCryptoKeyPair(result)) throw new Error('Expected single key');
  return result;
}

test(SUITE, 'ECDSA P-384', async () => {
  const pair = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  );
  const { publicKey, privateKey } = pair as CryptoKeyPair;

  const data = 'hello world';
  const signature = await subtle.sign(
    { name: 'ECDSA', hash: 'SHA-384' },
    privateKey as CryptoKey,
    encoder.encode(data),
  );

  expect(
    await subtle.verify(
      { name: 'ECDSA', hash: 'SHA-384' },
      publicKey as CryptoKey,
      signature,
      encoder.encode(data),
    ),
  ).to.equal(true);
});

test(SUITE, 'ECDSA with HashAlgorithmIdentifier', async () => {
  const pair = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const { publicKey, privateKey } = pair as CryptoKeyPair;
  const data = 'hello world';
  const signature = await subtle.sign(
    { name: 'ECDSA', hash: normalizeHashName('SHA-256') },
    privateKey as CryptoKey,
    encoder.encode(data),
  );
  expect(
    await subtle.verify(
      { name: 'ECDSA', hash: normalizeHashName('SHA-256') },
      publicKey as CryptoKey,
      signature,
      encoder.encode(data),
    ),
  ).to.equal(true);
});

// --- RSASSA-PKCS1-v1_5 Tests ---

test(SUITE, 'RSASSA-PKCS1-v1_5 with SHA-256 sign/verify', async () => {
  const keyPair = await generateKeyPairChecked(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );

  const signature = await subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    keyPair.privateKey,
    testData,
  );

  const isValid = await subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    keyPair.publicKey,
    signature,
    testData,
  );

  expect(isValid).to.equal(true);
});

test(SUITE, 'RSASSA-PKCS1-v1_5 with SHA-384 sign/verify', async () => {
  const keyPair = await generateKeyPairChecked(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-384',
    },
    true,
    ['sign', 'verify'],
  );

  const signature = await subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    keyPair.privateKey,
    testData,
  );

  const isValid = await subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    keyPair.publicKey,
    signature,
    testData,
  );

  expect(isValid).to.equal(true);
});

test(SUITE, 'RSASSA-PKCS1-v1_5 with SHA-512 sign/verify', async () => {
  const keyPair = await generateKeyPairChecked(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-512',
    },
    true,
    ['sign', 'verify'],
  );

  const signature = await subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    keyPair.privateKey,
    testData,
  );

  const isValid = await subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    keyPair.publicKey,
    signature,
    testData,
  );

  expect(isValid).to.equal(true);
});

test(
  SUITE,
  'RSASSA-PKCS1-v1_5 verify fails with tampered signature',
  async () => {
    const keyPair = await generateKeyPairChecked(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    );

    const signature = await subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      keyPair.privateKey,
      testData,
    );

    // Tamper with the signature
    const tamperedSig = new Uint8Array(signature);
    tamperedSig[0] = (tamperedSig[0] ?? 0) ^ 0xff;

    const isValid = await subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      keyPair.publicKey,
      tamperedSig,
      testData,
    );

    expect(isValid).to.equal(false);
  },
);

test(SUITE, 'RSASSA-PKCS1-v1_5 verify fails with wrong data', async () => {
  const keyPair = await generateKeyPairChecked(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );

  const signature = await subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    keyPair.privateKey,
    testData,
  );

  const wrongData = encoder.encode('Different message');
  const isValid = await subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    keyPair.publicKey,
    signature,
    wrongData,
  );

  expect(isValid).to.equal(false);
});

// --- RSA-PSS Tests ---

test(SUITE, 'RSA-PSS with SHA-256 sign/verify', async () => {
  const keyPair = await generateKeyPairChecked(
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );

  const signature = await subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    keyPair.privateKey,
    testData,
  );

  const isValid = await subtle.verify(
    { name: 'RSA-PSS', saltLength: 32 },
    keyPair.publicKey,
    signature,
    testData,
  );

  expect(isValid).to.equal(true);
});

test(SUITE, 'RSA-PSS with different salt lengths', async () => {
  const keyPair = await generateKeyPairChecked(
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );

  // Test with salt length 0
  const sig0 = await subtle.sign(
    { name: 'RSA-PSS', saltLength: 0 },
    keyPair.privateKey,
    testData,
  );
  const valid0 = await subtle.verify(
    { name: 'RSA-PSS', saltLength: 0 },
    keyPair.publicKey,
    sig0,
    testData,
  );
  expect(valid0).to.equal(true);

  // Test with salt length 64
  const sig64 = await subtle.sign(
    { name: 'RSA-PSS', saltLength: 64 },
    keyPair.privateKey,
    testData,
  );
  const valid64 = await subtle.verify(
    { name: 'RSA-PSS', saltLength: 64 },
    keyPair.publicKey,
    sig64,
    testData,
  );
  expect(valid64).to.equal(true);
});

test(SUITE, 'RSA-PSS with SHA-512 sign/verify', async () => {
  const keyPair = await generateKeyPairChecked(
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-512',
    },
    true,
    ['sign', 'verify'],
  );

  const signature = await subtle.sign(
    { name: 'RSA-PSS', saltLength: 64 },
    keyPair.privateKey,
    testData,
  );

  const isValid = await subtle.verify(
    { name: 'RSA-PSS', saltLength: 64 },
    keyPair.publicKey,
    signature,
    testData,
  );

  expect(isValid).to.equal(true);
});

// --- ECDSA Tests ---

test(SUITE, 'ECDSA P-256 with SHA-256 sign/verify', async () => {
  const keyPair = await generateKeyPairChecked(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify'],
  );

  const signature = await subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.privateKey,
    testData,
  );

  const isValid = await subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.publicKey,
    signature,
    testData,
  );

  expect(isValid).to.equal(true);
});

test(SUITE, 'ECDSA P-384 with SHA-384 sign/verify', async () => {
  const keyPair = await generateKeyPairChecked(
    {
      name: 'ECDSA',
      namedCurve: 'P-384',
    },
    true,
    ['sign', 'verify'],
  );

  const signature = await subtle.sign(
    { name: 'ECDSA', hash: 'SHA-384' },
    keyPair.privateKey,
    testData,
  );

  const isValid = await subtle.verify(
    { name: 'ECDSA', hash: 'SHA-384' },
    keyPair.publicKey,
    signature,
    testData,
  );

  expect(isValid).to.equal(true);
});

test(SUITE, 'ECDSA P-521 with SHA-512 sign/verify', async () => {
  const keyPair = await generateKeyPairChecked(
    {
      name: 'ECDSA',
      namedCurve: 'P-521',
    },
    true,
    ['sign', 'verify'],
  );

  const signature = await subtle.sign(
    { name: 'ECDSA', hash: 'SHA-512' },
    keyPair.privateKey,
    testData,
  );

  const isValid = await subtle.verify(
    { name: 'ECDSA', hash: 'SHA-512' },
    keyPair.publicKey,
    signature,
    testData,
  );

  expect(isValid).to.equal(true);
});

test(SUITE, 'ECDSA verify fails with tampered signature', async () => {
  const keyPair = await generateKeyPairChecked(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify'],
  );

  const signature = await subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.privateKey,
    testData,
  );

  // Tamper with the signature
  const tamperedSig = new Uint8Array(signature);
  tamperedSig[10] = (tamperedSig[10] ?? 0) ^ 0xff;

  const isValid = await subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.publicKey,
    tamperedSig,
    testData,
  );

  expect(isValid).to.equal(false);
});

// --- Ed25519 Tests ---

test(SUITE, 'Ed25519 sign/verify', async () => {
  const keyPair = await generateKeyPairChecked({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ]);

  const signature = await subtle.sign(
    { name: 'Ed25519' },
    keyPair.privateKey,
    testData,
  );

  // Ed25519 signature is always 64 bytes
  expect(signature.byteLength).to.equal(64);

  const isValid = await subtle.verify(
    { name: 'Ed25519' },
    keyPair.publicKey,
    signature,
    testData,
  );

  expect(isValid).to.equal(true);
});

test(SUITE, 'Ed25519 sign/verify with empty data', async () => {
  const keyPair = await generateKeyPairChecked({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ]);

  const signature = await subtle.sign(
    { name: 'Ed25519' },
    keyPair.privateKey,
    emptyData,
  );

  const isValid = await subtle.verify(
    { name: 'Ed25519' },
    keyPair.publicKey,
    signature,
    emptyData,
  );

  expect(isValid).to.equal(true);
});

test(SUITE, 'Ed25519 verify fails with tampered signature', async () => {
  const keyPair = await generateKeyPairChecked({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ]);

  const signature = await subtle.sign(
    { name: 'Ed25519' },
    keyPair.privateKey,
    testData,
  );

  const tamperedSig = new Uint8Array(signature);
  tamperedSig[0] = (tamperedSig[0] ?? 0) ^ 0xff;

  const isValid = await subtle.verify(
    { name: 'Ed25519' },
    keyPair.publicKey,
    tamperedSig,
    testData,
  );

  expect(isValid).to.equal(false);
});

test(SUITE, 'Ed25519 verify fails with wrong public key', async () => {
  const keyPair1 = await generateKeyPairChecked({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ]);

  const keyPair2 = await generateKeyPairChecked({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ]);

  const signature = await subtle.sign(
    { name: 'Ed25519' },
    keyPair1.privateKey,
    testData,
  );

  const isValid = await subtle.verify(
    { name: 'Ed25519' },
    keyPair2.publicKey, // Wrong public key
    signature,
    testData,
  );

  expect(isValid).to.equal(false);
});

// --- Ed448 Tests ---

test(SUITE, 'Ed448 sign/verify', async () => {
  const keyPair = await generateKeyPairChecked({ name: 'Ed448' }, true, [
    'sign',
    'verify',
  ]);

  const signature = await subtle.sign(
    { name: 'Ed448' },
    keyPair.privateKey,
    testData,
  );

  // Ed448 signature is always 114 bytes
  expect(signature.byteLength).to.equal(114);

  const isValid = await subtle.verify(
    { name: 'Ed448' },
    keyPair.publicKey,
    signature,
    testData,
  );

  expect(isValid).to.equal(true);
});

test(SUITE, 'Ed448 sign/verify with empty data', async () => {
  const keyPair = await generateKeyPairChecked({ name: 'Ed448' }, true, [
    'sign',
    'verify',
  ]);

  const signature = await subtle.sign(
    { name: 'Ed448' },
    keyPair.privateKey,
    emptyData,
  );

  const isValid = await subtle.verify(
    { name: 'Ed448' },
    keyPair.publicKey,
    signature,
    emptyData,
  );

  expect(isValid).to.equal(true);
});

// --- HMAC Tests ---

test(SUITE, 'HMAC SHA-256 sign/verify', async () => {
  const key = await generateSymmetricKeyChecked(
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  );

  const signature = await subtle.sign({ name: 'HMAC' }, key, testData);

  // HMAC-SHA-256 produces 32 bytes
  expect(signature.byteLength).to.equal(32);

  const isValid = await subtle.verify(
    { name: 'HMAC' },
    key,
    signature,
    testData,
  );

  expect(isValid).to.equal(true);
});

test(SUITE, 'HMAC SHA-512 sign/verify', async () => {
  const key = await generateSymmetricKeyChecked(
    { name: 'HMAC', hash: 'SHA-512' },
    true,
    ['sign', 'verify'],
  );

  const signature = await subtle.sign({ name: 'HMAC' }, key, testData);

  // HMAC-SHA-512 produces 64 bytes
  expect(signature.byteLength).to.equal(64);

  const isValid = await subtle.verify(
    { name: 'HMAC' },
    key,
    signature,
    testData,
  );

  expect(isValid).to.equal(true);
});

test(SUITE, 'HMAC verify fails with different key', async () => {
  const key1 = await generateSymmetricKeyChecked(
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  );

  const key2 = await generateSymmetricKeyChecked(
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  );

  const signature = await subtle.sign({ name: 'HMAC' }, key1, testData);

  const isValid = await subtle.verify(
    { name: 'HMAC' },
    key2, // Different key
    signature,
    testData,
  );

  expect(isValid).to.equal(false);
});

test(SUITE, 'HMAC verify fails with tampered signature', async () => {
  const key = await generateSymmetricKeyChecked(
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  );

  const signature = await subtle.sign({ name: 'HMAC' }, key, testData);

  const tamperedSig = new Uint8Array(signature);
  tamperedSig[0] = (tamperedSig[0] ?? 0) ^ 0xff;

  const isValid = await subtle.verify(
    { name: 'HMAC' },
    key,
    tamperedSig,
    testData,
  );

  expect(isValid).to.equal(false);
});

// --- Key Import/Export and Sign/Verify ---

// --- ML-DSA Tests ---

type MlDsaVariant = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
const MLDSA_VARIANTS: MlDsaVariant[] = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];
const MLDSA_SIGNATURE_SIZES: Record<MlDsaVariant, number> = {
  'ML-DSA-44': 2420,
  'ML-DSA-65': 3309,
  'ML-DSA-87': 4627,
};

for (const variant of MLDSA_VARIANTS) {
  test(SUITE, `${variant} sign/verify`, async () => {
    const keyPair = await generateKeyPairChecked({ name: variant }, true, [
      'sign',
      'verify',
    ]);

    const signature = await subtle.sign(
      { name: variant },
      keyPair.privateKey,
      testData,
    );

    expect(signature.byteLength).to.equal(MLDSA_SIGNATURE_SIZES[variant]);

    const isValid = await subtle.verify(
      { name: variant },
      keyPair.publicKey,
      signature,
      testData,
    );

    expect(isValid).to.equal(true);
  });

  test(SUITE, `${variant} sign/verify with empty data`, async () => {
    const keyPair = await generateKeyPairChecked({ name: variant }, true, [
      'sign',
      'verify',
    ]);

    const signature = await subtle.sign(
      { name: variant },
      keyPair.privateKey,
      emptyData,
    );

    expect(signature.byteLength).to.equal(MLDSA_SIGNATURE_SIZES[variant]);

    const isValid = await subtle.verify(
      { name: variant },
      keyPair.publicKey,
      signature,
      emptyData,
    );

    expect(isValid).to.equal(true);
  });

  test(SUITE, `${variant} verify fails with tampered signature`, async () => {
    const keyPair = await generateKeyPairChecked({ name: variant }, true, [
      'sign',
      'verify',
    ]);

    const signature = await subtle.sign(
      { name: variant },
      keyPair.privateKey,
      testData,
    );

    const tamperedSig = new Uint8Array(signature);
    tamperedSig[0] = (tamperedSig[0] ?? 0) ^ 0xff;

    const isValid = await subtle.verify(
      { name: variant },
      keyPair.publicKey,
      tamperedSig,
      testData,
    );

    expect(isValid).to.equal(false);
  });

  test(SUITE, `${variant} verify fails with wrong public key`, async () => {
    const keyPair1 = await generateKeyPairChecked({ name: variant }, true, [
      'sign',
      'verify',
    ]);
    const keyPair2 = await generateKeyPairChecked({ name: variant }, true, [
      'sign',
      'verify',
    ]);

    const signature = await subtle.sign(
      { name: variant },
      keyPair1.privateKey,
      testData,
    );

    const isValid = await subtle.verify(
      { name: variant },
      keyPair2.publicKey,
      signature,
      testData,
    );

    expect(isValid).to.equal(false);
  });
}

// --- Key Import/Export and Sign/Verify ---

test(SUITE, 'Sign with imported Ed25519 key', async () => {
  const keyPair = await generateKeyPairChecked({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ]);

  // Export and reimport private key
  const pkcs8 = await subtle.exportKey('pkcs8', keyPair.privateKey);
  const reimportedPrivate = await subtle.importKey(
    'pkcs8',
    pkcs8,
    { name: 'Ed25519' },
    true,
    ['sign'],
  );

  // Export and reimport public key
  const spki = await subtle.exportKey('spki', keyPair.publicKey);
  const reimportedPublic = await subtle.importKey(
    'spki',
    spki,
    { name: 'Ed25519' },
    true,
    ['verify'],
  );

  // Sign with reimported private key
  const signature = await subtle.sign(
    { name: 'Ed25519' },
    reimportedPrivate,
    testData,
  );

  // Verify with reimported public key
  const isValid = await subtle.verify(
    { name: 'Ed25519' },
    reimportedPublic,
    signature,
    testData,
  );

  expect(isValid).to.equal(true);
});

// --- Ed25519 Legacy API Tests (from cfrg suite) ---

const data1 = Buffer.from('hello world');

test(SUITE, 'ed25519 - sign/verify - round trip happy', async () => {
  const ed = new Ed('ed25519', {});
  await ed.generateKeyPair();
  const signature = await ed.sign(data1.buffer);
  const verified = await ed.verify(signature, data1.buffer);
  expect(verified).to.equal(true);
});

test(SUITE, 'ed25519 - sign/verify - round trip sad', async () => {
  const data2 = Buffer.from('goodbye cruel world');
  const ed = new Ed('ed25519', {});
  await ed.generateKeyPair();
  const signature = await ed.sign(data1.buffer);
  const verified = await ed.verify(signature, data2.buffer);
  expect(verified).to.equal(false);
});

test(
  SUITE,
  'ed25519 - sign/verify - bad signature does not verify',
  async () => {
    const ed = new Ed('ed25519', {});
    await ed.generateKeyPair();
    const signature = await ed.sign(data1.buffer);
    const signature2 = randomBytes(64).buffer;
    expect(ab2str(signature2)).not.to.equal(ab2str(signature));
    const verified = await ed.verify(signature2, data1.buffer);
    expect(verified).to.equal(false);
  },
);

test(
  SUITE,
  'ed25519 - sign/verify - switched args does not verify',
  async () => {
    const ed = new Ed('ed25519', {});
    await ed.generateKeyPair();
    const signature = await ed.sign(data1.buffer);
    const verified = await ed.verify(data1.buffer, signature);
    expect(verified).to.equal(false);
  },
);

test(
  SUITE,
  'ed25519 - sign/verify - non-internally generated private key',
  async () => {
    const pub = Buffer.from(
      'e106bf015ad54a64022295c7af2c35f9511eb37264a7722a9642eaac6c59a494',
      'hex',
    );
    const priv = Buffer.from(
      '5f27e170afc5091c4933d980c5fe86af997b91375115c6ee2c0fe4ea12400ed0',
      'hex',
    );

    const ed2 = new Ed('ed25519', {});
    const signature = await ed2.sign(data1.buffer, priv);
    const verified = await ed2.verify(signature, data1.buffer, pub);
    expect(verified).to.equal(true);
  },
);

test(SUITE, 'ed25519 - sign/verify - bad signature', async () => {
  let ed1: Ed | null = new Ed('ed25519', {});
  await ed1.generateKeyPair();
  const pub = ed1.getPublicKey();
  const priv = ed1.getPrivateKey();
  ed1 = null;

  const ed2 = new Ed('ed25519', {});
  const signature = await ed2.sign(data1.buffer, priv);
  const signature2 = randomBytes(64).buffer;
  expect(ab2str(signature2)).not.to.equal(ab2str(signature));
  const verified = await ed2.verify(signature2, data1.buffer, pub);
  expect(verified).to.equal(false);
});

test(
  SUITE,
  'ed25519 - sign/verify - bad verify with private key, not public',
  async () => {
    let ed1: Ed | null = new Ed('ed25519', {});
    await ed1.generateKeyPair();
    const priv = ed1.getPrivateKey();
    ed1 = null;

    const ed2 = new Ed('ed25519', {});
    const signature = await ed2.sign(data1.buffer, priv);
    const verified = await ed2.verify(signature, data1.buffer, priv);
    expect(verified).to.equal(false);
  },
);

test(SUITE, 'ed25519 - sign/verify - Uint8Arrays', () => {
  const data = { b: 'world', a: 'hello' };
  const encoder2 = new TextEncoder();
  const encode = (data: unknown): Uint8Array =>
    encoder2.encode(JSON.stringify(data));

  const ed1 = new Ed('ed25519', {});
  ed1.generateKeyPairSync();
  const pub = new Uint8Array(ed1.getPublicKey());
  const priv = new Uint8Array(ed1.getPrivateKey());

  const ed2 = new Ed('ed25519', {});
  const signature = new Uint8Array(ed2.signSync(encode(data), priv));
  const verified = ed2.verifySync(signature, encode(data), pub);
  expect(verified).to.equal(true);
});
