import { expect } from 'chai';
import type { CryptoKey, CryptoKeyPair, JWK } from 'react-native-quick-crypto';
import { subtle } from 'react-native-quick-crypto';
import { test } from '../util';

const SUITE = 'subtle.importKey/exportKey';

// Issue #806: Ensure JWK exports are RFC 7517 compliant (valid base64url, no periods)
test(SUITE, 'JWK export - RFC 7517 - RSA-OAEP', async () => {
  const { publicKey, privateKey } = (await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  )) as CryptoKeyPair;

  const exportedPub = (await subtle.exportKey(
    'jwk',
    publicKey as CryptoKey,
  )) as JWK;
  expect(exportedPub.n).to.match(/^[A-Za-z0-9_-]+$/);
  expect(exportedPub.e).to.match(/^[A-Za-z0-9_-]+$/);

  const exportedPriv = (await subtle.exportKey(
    'jwk',
    privateKey as CryptoKey,
  )) as JWK;
  expect(exportedPriv.n).to.match(/^[A-Za-z0-9_-]+$/);
  expect(exportedPriv.e).to.match(/^[A-Za-z0-9_-]+$/);
  expect(exportedPriv.d).to.match(/^[A-Za-z0-9_-]+$/);
  expect(exportedPriv.p).to.match(/^[A-Za-z0-9_-]+$/);
  expect(exportedPriv.q).to.match(/^[A-Za-z0-9_-]+$/);
  expect(exportedPriv.dp).to.match(/^[A-Za-z0-9_-]+$/);
  expect(exportedPriv.dq).to.match(/^[A-Za-z0-9_-]+$/);
  expect(exportedPriv.qi).to.match(/^[A-Za-z0-9_-]+$/);

  // Verify roundtrip
  const imported = await subtle.importKey(
    'jwk',
    exportedPriv,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt'],
  );
  expect(imported.type).to.equal('private');
});

test(SUITE, 'JWK export - RFC 7517 - ECDSA P-256', async () => {
  const { publicKey, privateKey } = (await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  const exportedPub = (await subtle.exportKey(
    'jwk',
    publicKey as CryptoKey,
  )) as JWK;
  expect(exportedPub.x).to.match(/^[A-Za-z0-9_-]+$/);
  expect(exportedPub.y).to.match(/^[A-Za-z0-9_-]+$/);

  const exportedPriv = (await subtle.exportKey(
    'jwk',
    privateKey as CryptoKey,
  )) as JWK;
  expect(exportedPriv.x).to.match(/^[A-Za-z0-9_-]+$/);
  expect(exportedPriv.y).to.match(/^[A-Za-z0-9_-]+$/);
  expect(exportedPriv.d).to.match(/^[A-Za-z0-9_-]+$/);

  const imported = await subtle.importKey(
    'jwk',
    exportedPriv,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign'],
  );
  expect(imported.type).to.equal('private');
});

test(SUITE, 'JWK export - RFC 7517 - ECDSA P-384', async () => {
  const { privateKey } = (await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  const exported = (await subtle.exportKey(
    'jwk',
    privateKey as CryptoKey,
  )) as JWK;
  expect(exported.x).to.match(/^[A-Za-z0-9_-]+$/);
  expect(exported.y).to.match(/^[A-Za-z0-9_-]+$/);
  expect(exported.d).to.match(/^[A-Za-z0-9_-]+$/);
});

test(SUITE, 'JWK export - RFC 7517 - ECDSA P-521', async () => {
  const { privateKey } = (await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-521' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  const exported = (await subtle.exportKey(
    'jwk',
    privateKey as CryptoKey,
  )) as JWK;
  expect(exported.x).to.match(/^[A-Za-z0-9_-]+$/);
  expect(exported.y).to.match(/^[A-Za-z0-9_-]+$/);
  expect(exported.d).to.match(/^[A-Za-z0-9_-]+$/);
});

test(SUITE, 'JWK export - RFC 7517 - ECDH P-256', async () => {
  const { privateKey } = (await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey'],
  )) as CryptoKeyPair;

  const exported = (await subtle.exportKey(
    'jwk',
    privateKey as CryptoKey,
  )) as JWK;
  expect(exported.x).to.match(/^[A-Za-z0-9_-]+$/);
  expect(exported.y).to.match(/^[A-Za-z0-9_-]+$/);
  expect(exported.d).to.match(/^[A-Za-z0-9_-]+$/);
});

// Test exact scenario from issue #806
test(SUITE, 'JWK export - issue #806 - no trailing periods', async () => {
  const { privateKey } = (await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  )) as CryptoKeyPair;

  const jwk = (await subtle.exportKey('jwk', privateKey as CryptoKey)) as JWK;

  // All fields must be valid base64url (only A-Za-z0-9_-)
  const fields = ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'] as const;
  for (const field of fields) {
    expect(jwk[field]).to.match(/^[A-Za-z0-9_-]+$/);
  }

  // Critical: can we import this JWK?
  const imported = await subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt'],
  );
  expect(imported.type).to.equal('private');
});

// Ed25519 JWK export/import roundtrip
test(SUITE, 'JWK export/import - Ed25519 keypair roundtrip', async () => {
  const { publicKey, privateKey } = (await subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  // Export public key as JWK
  const pubJwk = (await subtle.exportKey('jwk', publicKey as CryptoKey)) as JWK;
  expect(pubJwk.kty).to.equal('OKP');
  expect(pubJwk.crv).to.equal('Ed25519');
  expect(pubJwk.x).to.match(/^[A-Za-z0-9_-]+$/);
  expect(pubJwk.d).to.equal(undefined);

  // Export private key as JWK
  const privJwk = (await subtle.exportKey(
    'jwk',
    privateKey as CryptoKey,
  )) as JWK;
  expect(privJwk.kty).to.equal('OKP');
  expect(privJwk.crv).to.equal('Ed25519');
  expect(privJwk.x).to.match(/^[A-Za-z0-9_-]+$/);
  expect(privJwk.d).to.match(/^[A-Za-z0-9_-]+$/);

  // Import public key from JWK
  const importedPub = await subtle.importKey(
    'jwk',
    pubJwk,
    { name: 'Ed25519' },
    true,
    ['verify'],
  );
  expect(importedPub.type).to.equal('public');

  // Import private key from JWK
  const importedPriv = await subtle.importKey(
    'jwk',
    privJwk,
    { name: 'Ed25519' },
    true,
    ['sign'],
  );
  expect(importedPriv.type).to.equal('private');

  // Sign with imported private, verify with imported public
  const data = new Uint8Array([1, 2, 3, 4, 5]);
  const signature = await subtle.sign(
    { name: 'Ed25519' },
    importedPriv as CryptoKey,
    data,
  );
  const verified = await subtle.verify(
    { name: 'Ed25519' },
    importedPub as CryptoKey,
    signature,
    data,
  );
  expect(verified).to.equal(true);
});

// Ed448 JWK export/import roundtrip
test(SUITE, 'JWK export/import - Ed448 keypair roundtrip', async () => {
  const { publicKey, privateKey } = (await subtle.generateKey(
    { name: 'Ed448' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  const pubJwk = (await subtle.exportKey('jwk', publicKey as CryptoKey)) as JWK;
  expect(pubJwk.kty).to.equal('OKP');
  expect(pubJwk.crv).to.equal('Ed448');

  const privJwk = (await subtle.exportKey(
    'jwk',
    privateKey as CryptoKey,
  )) as JWK;
  expect(privJwk.kty).to.equal('OKP');
  expect(privJwk.crv).to.equal('Ed448');
  expect(privJwk.d).to.match(/^[A-Za-z0-9_-]+$/);

  // Roundtrip: import and sign/verify
  const importedPriv = await subtle.importKey(
    'jwk',
    privJwk,
    { name: 'Ed448' },
    true,
    ['sign'],
  );
  const importedPub = await subtle.importKey(
    'jwk',
    pubJwk,
    { name: 'Ed448' },
    true,
    ['verify'],
  );

  const data = new Uint8Array([10, 20, 30]);
  const signature = await subtle.sign(
    { name: 'Ed448' },
    importedPriv as CryptoKey,
    data,
  );
  const verified = await subtle.verify(
    { name: 'Ed448' },
    importedPub as CryptoKey,
    signature,
    data,
  );
  expect(verified).to.equal(true);
});
