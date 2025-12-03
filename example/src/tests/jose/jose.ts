import { expect } from 'chai';
import {
  exportJWK,
  importJWK,
  SignJWT,
  jwtVerify,
  CompactEncrypt,
  compactDecrypt,
  generateKeyPair as joseGenerateKeyPair,
  generateSecret as joseGenerateSecret,
} from 'jose';
import { subtle, CryptoKey } from 'react-native-quick-crypto';
import type { CryptoKeyPair } from 'react-native-quick-crypto';
import { test } from '../util';

const SUITE = 'jose';

// Helper to check Symbol.toStringTag
function getStringTag(obj: unknown): string | undefined {
  if (obj === null || obj === undefined) return undefined;
  return (obj as Record<symbol, string>)[Symbol.toStringTag];
}

// =============================================================================
// Symbol.toStringTag Tests
// =============================================================================

test(SUITE, 'CryptoKey has correct Symbol.toStringTag', async () => {
  const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
  expect(getStringTag(key)).to.equal('CryptoKey');
});

test(
  SUITE,
  'KeyObject (via CryptoKey.keyObject) has correct Symbol.toStringTag',
  async () => {
    const key = (await subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    )) as CryptoKey;
    expect(getStringTag(key.keyObject)).to.equal('KeyObject');
  },
);

test(SUITE, 'RSA CryptoKey has correct Symbol.toStringTag', async () => {
  const keyPair = (await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  )) as CryptoKeyPair;

  expect(getStringTag(keyPair.publicKey)).to.equal('CryptoKey');
  expect(getStringTag(keyPair.privateKey)).to.equal('CryptoKey');
  expect(getStringTag((keyPair.publicKey as CryptoKey).keyObject)).to.equal(
    'KeyObject',
  );
  expect(getStringTag((keyPair.privateKey as CryptoKey).keyObject)).to.equal(
    'KeyObject',
  );
});

// =============================================================================
// JWK Export/Import Tests
// =============================================================================

test(SUITE, 'exportJWK - RSA public key', async () => {
  const keyPair = (await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  )) as CryptoKeyPair;

  const jwk = await exportJWK(keyPair.publicKey as CryptoKey);
  expect(jwk.kty).to.equal('RSA');
  expect(jwk.n).to.match(/^[A-Za-z0-9_-]+$/);
  expect(jwk.e).to.equal('AQAB');
  expect(jwk.d).to.equal(undefined);
});

test(SUITE, 'exportJWK - RSA private key', async () => {
  const keyPair = (await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  )) as CryptoKeyPair;

  const jwk = await exportJWK(keyPair.privateKey as CryptoKey);
  expect(jwk.kty).to.equal('RSA');
  expect(jwk.n).to.match(/^[A-Za-z0-9_-]+$/);
  expect(jwk.e).to.equal('AQAB');
  expect(jwk.d).to.match(/^[A-Za-z0-9_-]+$/);
  expect(jwk.p).to.match(/^[A-Za-z0-9_-]+$/);
  expect(jwk.q).to.match(/^[A-Za-z0-9_-]+$/);
});

test(SUITE, 'exportJWK - EC P-256 key pair', async () => {
  const keyPair = (await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  const pubJwk = await exportJWK(keyPair.publicKey as CryptoKey);
  expect(pubJwk.kty).to.equal('EC');
  expect(pubJwk.crv).to.equal('P-256');
  expect(pubJwk.x).to.match(/^[A-Za-z0-9_-]+$/);
  expect(pubJwk.y).to.match(/^[A-Za-z0-9_-]+$/);
  expect(pubJwk.d).to.equal(undefined);

  const privJwk = await exportJWK(keyPair.privateKey as CryptoKey);
  expect(privJwk.kty).to.equal('EC');
  expect(privJwk.crv).to.equal('P-256');
  expect(privJwk.d).to.match(/^[A-Za-z0-9_-]+$/);
});

test(SUITE, 'exportJWK - HMAC secret key', async () => {
  const key = (await subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKey;

  const jwk = await exportJWK(key);
  expect(jwk.kty).to.equal('oct');
  expect(jwk.k).to.match(/^[A-Za-z0-9_-]+$/);
});

test(SUITE, 'importJWK - RSA public key roundtrip', async () => {
  const keyPair = (await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  )) as CryptoKeyPair;

  const jwk = await exportJWK(keyPair.publicKey as CryptoKey);
  const imported = await importJWK(jwk, 'RSA-OAEP-256');
  expect(getStringTag(imported)).to.equal('CryptoKey');
  expect((imported as CryptoKey).type).to.equal('public');
});

test(SUITE, 'importJWK - EC P-256 public key roundtrip', async () => {
  const keyPair = (await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  const jwk = await exportJWK(keyPair.publicKey as CryptoKey);
  const imported = await importJWK(jwk, 'ES256');
  expect(getStringTag(imported)).to.equal('CryptoKey');
  expect((imported as CryptoKey).type).to.equal('public');
});

// =============================================================================
// JWT Signing/Verification Tests (RSASSA-PKCS1-v1_5, RSA-PSS, ECDSA)
// =============================================================================

test(SUITE, 'SignJWT/jwtVerify - RS256 (RSASSA-PKCS1-v1_5)', async () => {
  const keyPair = (await subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  const jwt = await new SignJWT({
    sub: 'test-user',
    iat: Math.floor(Date.now() / 1000),
  })
    .setProtectedHeader({ alg: 'RS256' })
    .setExpirationTime('1h')
    .sign(keyPair.privateKey as CryptoKey);

  expect(jwt.split('.').length).to.equal(3);

  const { payload } = await jwtVerify(jwt, keyPair.publicKey as CryptoKey);
  expect(payload.sub).to.equal('test-user');
});

test(SUITE, 'SignJWT/jwtVerify - PS256 (RSA-PSS)', async () => {
  const keyPair = (await subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  const jwt = await new SignJWT({ sub: 'pss-user' })
    .setProtectedHeader({ alg: 'PS256' })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(keyPair.privateKey as CryptoKey);

  expect(jwt.split('.').length).to.equal(3);

  const { payload } = await jwtVerify(jwt, keyPair.publicKey as CryptoKey);
  expect(payload.sub).to.equal('pss-user');
});

test(SUITE, 'SignJWT/jwtVerify - ES256 (ECDSA P-256)', async () => {
  const keyPair = (await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  const jwt = await new SignJWT({ sub: 'ec-user' })
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(keyPair.privateKey as CryptoKey);

  expect(jwt.split('.').length).to.equal(3);

  const { payload } = await jwtVerify(jwt, keyPair.publicKey as CryptoKey);
  expect(payload.sub).to.equal('ec-user');
});

test(SUITE, 'SignJWT/jwtVerify - ES384 (ECDSA P-384)', async () => {
  const keyPair = (await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  const jwt = await new SignJWT({ sub: 'ec384-user' })
    .setProtectedHeader({ alg: 'ES384' })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(keyPair.privateKey as CryptoKey);

  const { payload } = await jwtVerify(jwt, keyPair.publicKey as CryptoKey);
  expect(payload.sub).to.equal('ec384-user');
});

test(SUITE, 'SignJWT/jwtVerify - HS256 (HMAC)', async () => {
  const key = (await subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKey;

  const jwt = await new SignJWT({ sub: 'hmac-user' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(key);

  expect(jwt.split('.').length).to.equal(3);

  const { payload } = await jwtVerify(jwt, key);
  expect(payload.sub).to.equal('hmac-user');
});

// =============================================================================
// JWE Encryption/Decryption Tests (RSA-OAEP)
// =============================================================================

test(SUITE, 'CompactEncrypt/compactDecrypt - RSA-OAEP-256', async () => {
  const keyPair = (await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  )) as CryptoKeyPair;

  const plaintext = new TextEncoder().encode('Hello, Jose!');

  const jwe = await new CompactEncrypt(plaintext)
    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
    .encrypt(keyPair.publicKey as CryptoKey);

  expect(jwe.split('.').length).to.equal(5);

  const { plaintext: decrypted } = await compactDecrypt(
    jwe,
    keyPair.privateKey as CryptoKey,
  );
  expect(new TextDecoder().decode(decrypted)).to.equal('Hello, Jose!');
});

test(SUITE, 'CompactEncrypt/compactDecrypt - RSA-OAEP (SHA-1)', async () => {
  const keyPair = (await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-1',
    },
    true,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  )) as CryptoKeyPair;

  const plaintext = new TextEncoder().encode('Secret message');

  const jwe = await new CompactEncrypt(plaintext)
    .setProtectedHeader({ alg: 'RSA-OAEP', enc: 'A128GCM' })
    .encrypt(keyPair.publicKey as CryptoKey);

  const { plaintext: decrypted } = await compactDecrypt(
    jwe,
    keyPair.privateKey as CryptoKey,
  );
  expect(new TextDecoder().decode(decrypted)).to.equal('Secret message');
});

// =============================================================================
// Algorithm Hash Property Normalization Tests
// =============================================================================

test(
  SUITE,
  'RSA key algorithm.hash is normalized to { name: string }',
  async () => {
    const keyPair = (await subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt'],
    )) as CryptoKeyPair;

    const pubKey = keyPair.publicKey as CryptoKey;
    const privKey = keyPair.privateKey as CryptoKey;

    // Check that hash is normalized to object format
    const pubAlgo = pubKey.algorithm;
    const privAlgo = privKey.algorithm;

    expect(typeof pubAlgo.hash).to.equal('object');
    expect((pubAlgo.hash as { name: string }).name).to.equal('SHA-256');
    expect(typeof privAlgo.hash).to.equal('object');
    expect((privAlgo.hash as { name: string }).name).to.equal('SHA-256');
  },
);

test(SUITE, 'RSA imported key algorithm.hash is normalized', async () => {
  const keyPair = (await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  )) as CryptoKeyPair;

  const exported = await subtle.exportKey(
    'spki',
    keyPair.publicKey as CryptoKey,
  );

  // Import with string hash format
  const imported = await subtle.importKey(
    'spki',
    exported,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt'],
  );

  // Verify hash is normalized
  expect(typeof imported.algorithm.hash).to.equal('object');
  expect((imported.algorithm.hash as { name: string }).name).to.equal(
    'SHA-256',
  );
});

// =============================================================================
// Cross-library Key Generation Tests
// =============================================================================

test(SUITE, 'jose generateKeyPair works with RNQC verification', async () => {
  const { publicKey, privateKey } = await joseGenerateKeyPair('RS256', {
    modulusLength: 2048,
    extractable: true,
  });

  const jwt = await new SignJWT({ test: 'value' })
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuedAt()
    .sign(privateKey);

  const { payload } = await jwtVerify(jwt, publicKey);
  expect(payload.test).to.equal('value');
});

test(SUITE, 'jose generateSecret works with RNQC', async () => {
  const secret = await joseGenerateSecret('HS256', { extractable: true });

  const jwt = await new SignJWT({ data: 'secret' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .sign(secret);

  const { payload } = await jwtVerify(jwt, secret);
  expect(payload.data).to.equal('secret');
});

// =============================================================================
// Edge Cases and Error Handling
// =============================================================================

test(SUITE, 'JWT with all standard claims', async () => {
  const keyPair = (await subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  const now = Math.floor(Date.now() / 1000);

  const jwt = await new SignJWT({
    sub: 'user123',
    name: 'Test User',
    admin: true,
    groups: ['users', 'admins'],
  })
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
    .setIssuer('rnqc-test')
    .setAudience('test-app')
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .setNotBefore(now - 60)
    .setJti('unique-token-id')
    .sign(keyPair.privateKey as CryptoKey);

  const { payload, protectedHeader } = await jwtVerify(
    jwt,
    keyPair.publicKey as CryptoKey,
    {
      issuer: 'rnqc-test',
      audience: 'test-app',
    },
  );

  expect(protectedHeader.alg).to.equal('RS256');
  expect(protectedHeader.typ).to.equal('JWT');
  expect(payload.sub).to.equal('user123');
  expect(payload.iss).to.equal('rnqc-test');
  expect(payload.aud).to.equal('test-app');
  expect(payload.name).to.equal('Test User');
  expect(payload.admin).to.equal(true);
  expect(payload.groups).to.have.members(['users', 'admins']);
  expect(payload.jti).to.equal('unique-token-id');
});

test(SUITE, 'JWE with A256GCM content encryption', async () => {
  const keyPair = (await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  )) as CryptoKeyPair;

  const sensitiveData = JSON.stringify({
    creditCard: '4111-1111-1111-1111',
    expiry: '12/25',
  });

  const jwe = await new CompactEncrypt(new TextEncoder().encode(sensitiveData))
    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
    .encrypt(keyPair.publicKey as CryptoKey);

  const { plaintext } = await compactDecrypt(
    jwe,
    keyPair.privateKey as CryptoKey,
  );
  const decrypted = JSON.parse(new TextDecoder().decode(plaintext));

  expect(decrypted.creditCard).to.equal('4111-1111-1111-1111');
  expect(decrypted.expiry).to.equal('12/25');
});
