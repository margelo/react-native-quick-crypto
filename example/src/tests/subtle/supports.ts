import { expect } from 'chai';
import { Subtle } from 'react-native-quick-crypto';
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
test(SUITE, 'deriveBits: HKDF is supported', () => {
  expect(Subtle.supports('deriveBits', 'HKDF')).to.equal(true);
});

test(SUITE, 'deriveBits: PBKDF2 is supported', () => {
  expect(Subtle.supports('deriveBits', 'PBKDF2')).to.equal(true);
});

test(SUITE, 'deriveBits: X25519 is supported', () => {
  expect(Subtle.supports('deriveBits', 'X25519')).to.equal(true);
});

test(SUITE, 'deriveBits: AES-GCM is not supported', () => {
  expect(Subtle.supports('deriveBits', 'AES-GCM')).to.equal(false);
});

// --- DeriveKey ---
test(SUITE, 'deriveKey: HKDF is supported', () => {
  expect(Subtle.supports('deriveKey', 'HKDF')).to.equal(true);
});

test(SUITE, 'deriveKey: HKDF with AES-GCM output is supported', () => {
  expect(Subtle.supports('deriveKey', 'HKDF', 'AES-GCM')).to.equal(true);
});

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

// --- Invalid operation ---
test(SUITE, 'invalid operation returns false', () => {
  expect(Subtle.supports('nonexistent', 'AES-GCM')).to.equal(false);
});

// --- Invalid algorithm ---
test(SUITE, 'invalid algorithm returns false', () => {
  expect(Subtle.supports('encrypt', 'FAKE-ALGO' as never)).to.equal(false);
});
