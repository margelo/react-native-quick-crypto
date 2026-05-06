import { expect } from 'chai';
import { Subtle, subtle } from 'react-native-quick-crypto';
import { test } from '../util';

const SUITE = 'subtle.supports';

// --- Encrypt ---
test(SUITE, 'encrypt: AES-GCM is supported', () => {
  expect(Subtle.supports('encrypt', 'AES-GCM')).to.equal(true);
});

test(SUITE, 'encrypt: RSA-OAEP is supported', () => {
  expect(Subtle.supports('encrypt', 'RSA-OAEP')).to.equal(true);
});

test(SUITE, 'encrypt: ChaCha20-Poly1305 is supported', () => {
  expect(Subtle.supports('encrypt', 'ChaCha20-Poly1305')).to.equal(true);
});

test(SUITE, 'encrypt: HMAC is not supported', () => {
  expect(Subtle.supports('encrypt', 'HMAC')).to.equal(false);
});

test(SUITE, 'encrypt: Ed25519 is not supported', () => {
  expect(Subtle.supports('encrypt', 'Ed25519')).to.equal(false);
});

// --- Sign ---
test(SUITE, 'sign: Ed25519 is supported', () => {
  expect(Subtle.supports('sign', 'Ed25519')).to.equal(true);
});

test(SUITE, 'sign: ECDSA is supported', () => {
  expect(Subtle.supports('sign', 'ECDSA')).to.equal(true);
});

test(SUITE, 'sign: HMAC is supported', () => {
  expect(Subtle.supports('sign', 'HMAC')).to.equal(true);
});

test(SUITE, 'sign: ML-DSA-65 is supported', () => {
  expect(Subtle.supports('sign', 'ML-DSA-65')).to.equal(true);
});

test(SUITE, 'sign: AES-GCM is not supported', () => {
  expect(Subtle.supports('sign', 'AES-GCM')).to.equal(false);
});

// --- Digest ---
test(SUITE, 'digest: SHA-256 is supported', () => {
  expect(Subtle.supports('digest', 'SHA-256')).to.equal(true);
});

test(SUITE, 'digest: SHA-512 is supported', () => {
  expect(Subtle.supports('digest', 'SHA-512')).to.equal(true);
});

// --- GenerateKey ---
test(SUITE, 'generateKey: Ed25519 is supported', () => {
  expect(Subtle.supports('generateKey', 'Ed25519')).to.equal(true);
});

test(SUITE, 'generateKey: X25519 is supported', () => {
  expect(Subtle.supports('generateKey', 'X25519')).to.equal(true);
});

test(SUITE, 'generateKey: HKDF is not supported', () => {
  expect(Subtle.supports('generateKey', 'HKDF')).to.equal(false);
});

// --- DeriveBits ---
// HKDF/PBKDF2/Argon2 require an explicit length per Node webcrypto.js:1689-1714.
test(SUITE, 'deriveBits: HKDF with length is supported', () => {
  expect(Subtle.supports('deriveBits', 'HKDF', 256)).to.equal(true);
});

test(SUITE, 'deriveBits: PBKDF2 with length is supported', () => {
  expect(Subtle.supports('deriveBits', 'PBKDF2', 256)).to.equal(true);
});

test(SUITE, 'deriveBits: HKDF without length is not supported', () => {
  expect(Subtle.supports('deriveBits', 'HKDF')).to.equal(false);
});

test(SUITE, 'deriveBits: X25519 is supported', () => {
  expect(Subtle.supports('deriveBits', 'X25519')).to.equal(true);
});

test(SUITE, 'deriveBits: AES-GCM is not supported', () => {
  expect(Subtle.supports('deriveBits', 'AES-GCM')).to.equal(false);
});

// --- DeriveKey ---
test(SUITE, 'deriveKey: HKDF + AES-GCM with length 256 is supported', () => {
  expect(
    Subtle.supports('deriveKey', 'HKDF', { name: 'AES-GCM', length: 256 }),
  ).to.equal(true);
});

// AES key length is required for getKeyLength — Node webcrypto.js:269-279.
test(SUITE, 'deriveKey: HKDF + AES-GCM without length is not supported', () => {
  expect(Subtle.supports('deriveKey', 'HKDF', 'AES-GCM')).to.equal(false);
});

test(
  SUITE,
  'deriveKey: HKDF without additional algorithm returns false',
  () => {
    expect(Subtle.supports('deriveKey', 'HKDF')).to.equal(false);
  },
);

// --- GetPublicKey ---
test(SUITE, 'getPublicKey: Ed25519 is supported', () => {
  expect(Subtle.supports('getPublicKey', 'Ed25519')).to.equal(true);
});

test(SUITE, 'getPublicKey: RSA-PSS is supported', () => {
  expect(Subtle.supports('getPublicKey', 'RSA-PSS')).to.equal(true);
});

test(SUITE, 'getPublicKey: X25519 is supported', () => {
  expect(Subtle.supports('getPublicKey', 'X25519')).to.equal(true);
});

test(SUITE, 'getPublicKey: HMAC is not supported', () => {
  expect(Subtle.supports('getPublicKey', 'HMAC')).to.equal(false);
});

test(SUITE, 'getPublicKey: AES-GCM is not supported', () => {
  expect(Subtle.supports('getPublicKey', 'AES-GCM')).to.equal(false);
});

// --- WrapKey ---
test(SUITE, 'wrapKey: AES-KW is supported', () => {
  expect(Subtle.supports('wrapKey', 'AES-KW')).to.equal(true);
});

test(SUITE, 'wrapKey: Ed25519 is not supported', () => {
  expect(Subtle.supports('wrapKey', 'Ed25519')).to.equal(false);
});

test(SUITE, 'wrapKey: AES-KW with AES-GCM exportKey decomposition', () => {
  expect(Subtle.supports('wrapKey', 'AES-KW', 'AES-GCM')).to.equal(true);
});

test(SUITE, 'wrapKey: AES-KW with FAKE exportKey decomposition', () => {
  expect(Subtle.supports('wrapKey', 'AES-KW', 'FAKE' as never)).to.equal(false);
});

// --- UnwrapKey ---
test(SUITE, 'unwrapKey: AES-KW is supported', () => {
  expect(Subtle.supports('unwrapKey', 'AES-KW')).to.equal(true);
});

test(SUITE, 'unwrapKey: AES-KW with AES-GCM importKey decomposition', () => {
  expect(Subtle.supports('unwrapKey', 'AES-KW', 'AES-GCM')).to.equal(true);
});

test(SUITE, 'unwrapKey: AES-KW with FAKE importKey decomposition', () => {
  expect(Subtle.supports('unwrapKey', 'AES-KW', 'FAKE' as never)).to.equal(
    false,
  );
});

// --- EncapsulateKey ---
test(SUITE, 'encapsulateKey: ML-KEM-768 + AES-GCM is supported', () => {
  expect(Subtle.supports('encapsulateKey', 'ML-KEM-768', 'AES-GCM')).to.equal(
    true,
  );
});

test(SUITE, 'encapsulateKey: ML-KEM-768 + Ed25519 is not supported', () => {
  expect(Subtle.supports('encapsulateKey', 'ML-KEM-768', 'Ed25519')).to.equal(
    false,
  );
});

test(
  SUITE,
  'encapsulateKey: ML-KEM-768 + HMAC default length supported',
  () => {
    expect(Subtle.supports('encapsulateKey', 'ML-KEM-768', 'HMAC')).to.equal(
      true,
    );
  },
);

test(SUITE, 'encapsulateKey: ML-KEM-768 + HMAC length 256 supported', () => {
  expect(
    Subtle.supports('encapsulateKey', 'ML-KEM-768', {
      name: 'HMAC',
      length: 256,
    }),
  ).to.equal(true);
});

test(
  SUITE,
  'encapsulateKey: ML-KEM-768 + HMAC non-default length not supported',
  () => {
    expect(
      Subtle.supports('encapsulateKey', 'ML-KEM-768', {
        name: 'HMAC',
        length: 512,
      }),
    ).to.equal(false);
  },
);

// --- DeriveBits per-algorithm length validators ---
test(SUITE, 'deriveBits: HKDF with non-multiple-of-8 length rejected', () => {
  expect(Subtle.supports('deriveBits', 'HKDF', 257)).to.equal(false);
});

test(SUITE, 'deriveBits: PBKDF2 with non-multiple-of-8 length rejected', () => {
  expect(Subtle.supports('deriveBits', 'PBKDF2', 257)).to.equal(false);
});

test(SUITE, 'deriveBits: Argon2id length below 32 rejected', () => {
  expect(Subtle.supports('deriveBits', 'Argon2id', 16)).to.equal(false);
});

test(SUITE, 'deriveBits: Argon2id length 32 supported', () => {
  expect(Subtle.supports('deriveBits', 'Argon2id', 32)).to.equal(true);
});

// --- Instance access ---
test(SUITE, 'subtle.supports() instance method works', () => {
  expect(subtle.supports('encrypt', 'AES-GCM')).to.equal(true);
  expect(subtle.supports('encrypt', 'HMAC')).to.equal(false);
});

// --- Invalid operation ---
test(SUITE, 'invalid operation returns false', () => {
  expect(Subtle.supports('nonexistent', 'AES-GCM')).to.equal(false);
});

// --- Invalid algorithm ---
test(SUITE, 'invalid algorithm returns false', () => {
  expect(Subtle.supports('encrypt', 'FAKE-ALGO' as never)).to.equal(false);
});
