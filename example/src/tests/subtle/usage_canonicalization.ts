import { expect } from 'chai';
import type {
  CryptoKey,
  JWK,
  WebCryptoKeyPair,
} from 'react-native-quick-crypto';
import crypto, { subtle } from 'react-native-quick-crypto';
import { test } from '../util';

// Issue #1000 / Node commit fe7ebccd0ce ("crypto: deduplicate and canonicalize
// CryptoKey usages"). `CryptoKey.usages` (and JWK `key_ops` derived from it)
// must be deduplicated and returned in this canonical order:
//
//   encrypt, decrypt, sign, verify, deriveKey, deriveBits,
//   wrapKey, unwrapKey, encapsulateKey, encapsulateBits,
//   decapsulateKey, decapsulateBits

const SUITE = 'subtle.usage-canonicalization';

// --- generateKey: symmetric (single CryptoKey) ----------------------------

const symmetricVectors: Array<{
  name: string;
  // SubtleAlgorithm types vary across algorithms; loose typing is fine here.
  algorithm: object;
  usages: string[];
  expected: string[];
}> = [
  {
    name: 'HMAC',
    algorithm: { name: 'HMAC', hash: 'SHA-256' },
    usages: ['verify', 'sign', 'verify', 'sign'],
    expected: ['sign', 'verify'],
  },
  {
    name: 'AES-CTR',
    algorithm: { name: 'AES-CTR', length: 128 },
    usages: [
      'wrapKey',
      'decrypt',
      'encrypt',
      'unwrapKey',
      'wrapKey',
      'encrypt',
    ],
    expected: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  },
  {
    name: 'AES-CBC dedup-only',
    algorithm: { name: 'AES-CBC', length: 128 },
    usages: ['encrypt', 'encrypt'],
    expected: ['encrypt'],
  },
  {
    name: 'AES-GCM',
    algorithm: { name: 'AES-GCM', length: 128 },
    usages: ['decrypt', 'encrypt', 'decrypt'],
    expected: ['encrypt', 'decrypt'],
  },
];

for (const { name, algorithm, usages, expected } of symmetricVectors) {
  test(SUITE, `generateKey ${name} usages canonical + deduped`, async () => {
    const key = (await subtle.generateKey(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      algorithm as any,
      true,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      usages as any,
    )) as CryptoKey;
    expect(key.usages).to.deep.equal(expected);
    expect(key.usages.length).to.equal(expected.length);
  });
}

// --- generateKey: asymmetric (CryptoKeyPair) ------------------------------

type PairVector = {
  name: string;
  algorithm: object;
  usages: string[];
  publicExpected: string[];
  privateExpected: string[];
};

const asymmetricVectors: PairVector[] = [
  {
    name: 'RSA-OAEP',
    algorithm: {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    usages: [
      'wrapKey',
      'unwrapKey',
      'decrypt',
      'encrypt',
      'unwrapKey',
      'wrapKey',
      'decrypt',
      'encrypt',
    ],
    publicExpected: ['encrypt', 'wrapKey'],
    privateExpected: ['decrypt', 'unwrapKey'],
  },
  {
    name: 'RSA-PSS',
    algorithm: {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    usages: ['verify', 'sign', 'verify', 'sign'],
    publicExpected: ['verify'],
    privateExpected: ['sign'],
  },
  {
    name: 'ECDSA P-256',
    algorithm: { name: 'ECDSA', namedCurve: 'P-256' },
    usages: ['verify', 'sign', 'verify', 'sign', 'verify'],
    publicExpected: ['verify'],
    privateExpected: ['sign'],
  },
  {
    name: 'ECDH P-256',
    algorithm: { name: 'ECDH', namedCurve: 'P-256' },
    usages: ['deriveBits', 'deriveKey', 'deriveBits', 'deriveKey'],
    publicExpected: [],
    privateExpected: ['deriveKey', 'deriveBits'],
  },
  {
    name: 'Ed25519',
    algorithm: { name: 'Ed25519' },
    usages: ['verify', 'sign', 'verify', 'sign'],
    publicExpected: ['verify'],
    privateExpected: ['sign'],
  },
  {
    name: 'X25519',
    algorithm: { name: 'X25519' },
    usages: ['deriveBits', 'deriveKey', 'deriveBits', 'deriveKey'],
    publicExpected: [],
    privateExpected: ['deriveKey', 'deriveBits'],
  },
  {
    name: 'ML-DSA-65',
    algorithm: { name: 'ML-DSA-65' },
    usages: ['verify', 'sign', 'verify', 'sign'],
    publicExpected: ['verify'],
    privateExpected: ['sign'],
  },
  {
    name: 'ML-KEM-768',
    algorithm: { name: 'ML-KEM-768' },
    usages: [
      'decapsulateBits',
      'encapsulateBits',
      'decapsulateKey',
      'encapsulateKey',
      'decapsulateBits',
      'encapsulateBits',
    ],
    publicExpected: ['encapsulateKey', 'encapsulateBits'],
    privateExpected: ['decapsulateKey', 'decapsulateBits'],
  },
];

for (const v of asymmetricVectors) {
  test(SUITE, `generateKey ${v.name} usages canonical + deduped`, async () => {
    const { publicKey, privateKey } = (await subtle.generateKey(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      v.algorithm as any,
      true,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      v.usages as any,
    )) as WebCryptoKeyPair;
    expect(publicKey.usages, `${v.name} publicKey`).to.deep.equal(
      v.publicExpected,
    );
    expect(privateKey.usages, `${v.name} privateKey`).to.deep.equal(
      v.privateExpected,
    );
  });
}

// --- importKey: raw symmetric ---------------------------------------------

test(SUITE, 'importKey raw AES-GCM dedupes + canonicalizes', async () => {
  const key = await subtle.importKey(
    'raw',
    new Uint8Array(16),
    { name: 'AES-GCM' },
    true,
    ['decrypt', 'encrypt', 'decrypt'],
  );
  expect(key.usages).to.deep.equal(['encrypt', 'decrypt']);
});

test(SUITE, 'importKey raw HMAC dedupes + canonicalizes', async () => {
  const key = await subtle.importKey(
    'raw',
    new Uint8Array(32),
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['verify', 'sign', 'verify', 'sign'],
  );
  expect(key.usages).to.deep.equal(['sign', 'verify']);
});

// HKDF / PBKDF2 (importGenericSecretKey path).
for (const name of ['HKDF', 'PBKDF2']) {
  test(SUITE, `importKey raw ${name} dedupes + canonicalizes`, async () => {
    const key = await subtle.importKey(
      'raw',
      new Uint8Array(16),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      name as any,
      false,
      ['deriveBits', 'deriveKey', 'deriveBits', 'deriveKey'],
    );
    expect(key.usages).to.deep.equal(['deriveKey', 'deriveBits']);
  });
}

// --- importKey: JWK -------------------------------------------------------

test(SUITE, 'importKey jwk AES-CBC dedupes', async () => {
  const jwk: JWK = {
    kty: 'oct',
    k: 'AAAAAAAAAAAAAAAAAAAAAA',
    alg: 'A128CBC',
  };
  const key = await subtle.importKey('jwk', jwk, { name: 'AES-CBC' }, true, [
    'decrypt',
    'encrypt',
    'decrypt',
  ]);
  expect(key.usages).to.deep.equal(['encrypt', 'decrypt']);
});

// --- KeyObject.toCryptoKey() ----------------------------------------------

test(SUITE, 'createSecretKey().toCryptoKey() HMAC dedupes', () => {
  const keyObject = crypto.createSecretKey(new Uint8Array(32));
  const key = keyObject.toCryptoKey({ name: 'HMAC', hash: 'SHA-256' }, true, [
    'verify',
    'sign',
    'verify',
    'sign',
  ]);
  expect(key.usages).to.deep.equal(['sign', 'verify']);
});

test(SUITE, 'createSecretKey().toCryptoKey() AES-GCM dedupes', () => {
  const keyObject = crypto.createSecretKey(new Uint8Array(16));
  const key = keyObject.toCryptoKey({ name: 'AES-GCM' }, true, [
    'decrypt',
    'encrypt',
    'decrypt',
  ]);
  expect(key.usages).to.deep.equal(['encrypt', 'decrypt']);
});

// --- JWK export `key_ops` mirrors canonical usages ------------------------

test(SUITE, 'exportKey jwk AES-CTR key_ops canonical', async () => {
  const key = (await subtle.generateKey(
    { name: 'AES-CTR', length: 128 },
    true,
    ['wrapKey', 'encrypt', 'decrypt', 'encrypt', 'wrapKey', 'unwrapKey'],
  )) as CryptoKey;
  const jwk = (await subtle.exportKey('jwk', key)) as JWK;
  expect(jwk.key_ops).to.deep.equal([
    'encrypt',
    'decrypt',
    'wrapKey',
    'unwrapKey',
  ]);
});

test(SUITE, 'exportKey jwk HMAC key_ops canonical', async () => {
  const key = (await subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['verify', 'sign', 'verify', 'sign'],
  )) as CryptoKey;
  const jwk = (await subtle.exportKey('jwk', key)) as JWK;
  expect(jwk.key_ops).to.deep.equal(['sign', 'verify']);
});

test(SUITE, 'exportKey jwk RSA-OAEP pair key_ops canonical', async () => {
  const { publicKey, privateKey } = (await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    [
      'wrapKey',
      'unwrapKey',
      'decrypt',
      'encrypt',
      'unwrapKey',
      'wrapKey',
      'decrypt',
      'encrypt',
    ],
  )) as WebCryptoKeyPair;

  const publicJwk = (await subtle.exportKey('jwk', publicKey)) as JWK;
  const privateJwk = (await subtle.exportKey('jwk', privateKey)) as JWK;
  expect(publicJwk.key_ops).to.deep.equal(['encrypt', 'wrapKey']);
  expect(privateJwk.key_ops).to.deep.equal(['decrypt', 'unwrapKey']);
});

test(SUITE, 'exportKey jwk ML-KEM-768 pair key_ops canonical', async () => {
  const { publicKey, privateKey } = (await subtle.generateKey(
    { name: 'ML-KEM-768' },
    true,
    [
      'decapsulateBits',
      'encapsulateBits',
      'decapsulateKey',
      'encapsulateKey',
      'decapsulateBits',
      'encapsulateBits',
    ],
  )) as WebCryptoKeyPair;

  const publicJwk = (await subtle.exportKey('jwk', publicKey)) as JWK;
  const privateJwk = (await subtle.exportKey('jwk', privateKey)) as JWK;
  expect(publicJwk.key_ops).to.deep.equal([
    'encapsulateKey',
    'encapsulateBits',
  ]);
  expect(privateJwk.key_ops).to.deep.equal([
    'decapsulateKey',
    'decapsulateBits',
  ]);
});
