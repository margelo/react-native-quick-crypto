import { expect } from 'chai';
import { Subtle } from 'react-native-quick-crypto';
import type { SubtleAlgorithm } from 'react-native-quick-crypto';
import { test } from '../util';

const SUITE = 'subtle.supports';

// --- Encrypt ---
// Strict WebIDL normalization (#1025): AeadParams.iv is required, so passing
// just the string returns false. Full params are needed to assert support.
test(SUITE, 'encrypt: AES-GCM with iv is supported', () => {
  expect(
    Subtle.supports('encrypt', {
      name: 'AES-GCM',
      iv: new Uint8Array(12),
    }),
  ).to.equal(true);
});

test(SUITE, 'encrypt: AES-GCM without iv is not supported', () => {
  expect(Subtle.supports('encrypt', 'AES-GCM')).to.equal(false);
});

test(SUITE, 'encrypt: AES-CBC with invalid iv length is not supported', () => {
  expect(
    Subtle.supports('encrypt', {
      name: 'AES-CBC',
      iv: new Uint8Array(12),
    }),
  ).to.equal(false);
});

test(SUITE, 'encrypt: AES-GCM with invalid tagLength is not supported', () => {
  expect(
    Subtle.supports('encrypt', {
      name: 'AES-GCM',
      iv: new Uint8Array(12),
      tagLength: 24,
    }),
  ).to.equal(false);
});

test(SUITE, 'encrypt: RSA-OAEP is supported', () => {
  expect(Subtle.supports('encrypt', 'RSA-OAEP')).to.equal(true);
});

test(SUITE, 'encrypt: ChaCha20-Poly1305 with iv is supported', () => {
  expect(
    Subtle.supports('encrypt', {
      name: 'ChaCha20-Poly1305',
      iv: new Uint8Array(12),
    }),
  ).to.equal(true);
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

// EcdsaParams.hash is required under strict normalization (#1025).
test(SUITE, 'sign: ECDSA with hash is supported', () => {
  expect(Subtle.supports('sign', { name: 'ECDSA', hash: 'SHA-256' })).to.equal(
    true,
  );
});

test(SUITE, 'sign: ECDSA without hash is not supported', () => {
  expect(Subtle.supports('sign', 'ECDSA')).to.equal(false);
});

test(SUITE, 'sign: ECDSA with non-SHA hash is not supported', () => {
  expect(Subtle.supports('sign', { name: 'ECDSA', hash: 'MD5' })).to.equal(
    false,
  );
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

test(
  SUITE,
  'digest: TurboSHAKE128 invalid outputLength is not supported',
  () => {
    expect(
      Subtle.supports('digest', {
        name: 'TurboSHAKE128',
        outputLength: 0,
      }),
    ).to.equal(false);
  },
);

test(
  SUITE,
  'digest: TurboSHAKE128 invalid domainSeparation is not supported',
  () => {
    expect(
      Subtle.supports('digest', {
        name: 'TurboSHAKE128',
        outputLength: 256,
        domainSeparation: 0x80,
      }),
    ).to.equal(false);
  },
);

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
// Under strict normalization (#1025) the dictionary members are also required.
const HKDF_FULL: SubtleAlgorithm = {
  name: 'HKDF',
  hash: 'SHA-256',
  salt: new Uint8Array(0),
  info: new Uint8Array(0),
};
const PBKDF2_FULL: SubtleAlgorithm = {
  name: 'PBKDF2',
  hash: 'SHA-256',
  salt: new Uint8Array(8),
  iterations: 1000,
};

test(SUITE, 'deriveBits: HKDF with full params + length is supported', () => {
  expect(Subtle.supports('deriveBits', HKDF_FULL, 256)).to.equal(true);
});

test(SUITE, 'deriveBits: PBKDF2 with full params + length is supported', () => {
  expect(Subtle.supports('deriveBits', PBKDF2_FULL, 256)).to.equal(true);
});

test(SUITE, 'deriveBits: PBKDF2 with zero iterations is not supported', () => {
  expect(
    Subtle.supports(
      'deriveBits',
      {
        ...PBKDF2_FULL,
        iterations: 0,
      },
      256,
    ),
  ).to.equal(false);
});

test(SUITE, 'deriveBits: HKDF missing salt/info is not supported', () => {
  expect(Subtle.supports('deriveBits', 'HKDF', 256)).to.equal(false);
});

test(SUITE, 'deriveBits: HKDF without length is not supported', () => {
  expect(Subtle.supports('deriveBits', HKDF_FULL)).to.equal(false);
});

// EcdhKeyDeriveParams.public (a CryptoKey) is required, so calling
// supports('deriveBits', 'X25519') without it returns false under strict
// normalization — mirrors Node's behavior.
test(SUITE, 'deriveBits: X25519 without public key is not supported', () => {
  expect(Subtle.supports('deriveBits', 'X25519')).to.equal(false);
});

test(SUITE, 'deriveBits: AES-GCM is not supported', () => {
  expect(Subtle.supports('deriveBits', 'AES-GCM')).to.equal(false);
});

// --- DeriveKey ---
test(SUITE, 'deriveKey: HKDF + AES-GCM with length 256 is supported', () => {
  expect(
    Subtle.supports('deriveKey', HKDF_FULL, {
      name: 'AES-GCM',
      length: 256,
    }),
  ).to.equal(true);
});

// AES key length is required for getKeyLength — Node webcrypto.js:269-279.
test(SUITE, 'deriveKey: HKDF + AES-GCM without length is not supported', () => {
  expect(Subtle.supports('deriveKey', HKDF_FULL, 'AES-GCM')).to.equal(false);
});

test(
  SUITE,
  'deriveKey: HKDF without additional algorithm returns false',
  () => {
    expect(Subtle.supports('deriveKey', HKDF_FULL)).to.equal(false);
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

// Under strict normalization (#1025), HmacImportParams.hash is required.
test(
  SUITE,
  'encapsulateKey: ML-KEM-768 + HMAC without hash is not supported',
  () => {
    expect(Subtle.supports('encapsulateKey', 'ML-KEM-768', 'HMAC')).to.equal(
      false,
    );
  },
);

test(
  SUITE,
  'encapsulateKey: ML-KEM-768 + HMAC with hash + length 256 supported',
  () => {
    expect(
      Subtle.supports('encapsulateKey', 'ML-KEM-768', {
        name: 'HMAC',
        hash: 'SHA-256',
        length: 256,
      }),
    ).to.equal(true);
  },
);

test(
  SUITE,
  'encapsulateKey: ML-KEM-768 + HMAC non-default length not supported',
  () => {
    expect(
      Subtle.supports('encapsulateKey', 'ML-KEM-768', {
        name: 'HMAC',
        hash: 'SHA-256',
        length: 512,
      }),
    ).to.equal(false);
  },
);

// --- DeriveBits per-algorithm length validators ---
test(SUITE, 'deriveBits: HKDF with non-multiple-of-8 length rejected', () => {
  expect(Subtle.supports('deriveBits', HKDF_FULL, 257)).to.equal(false);
});

test(SUITE, 'deriveBits: PBKDF2 with non-multiple-of-8 length rejected', () => {
  expect(Subtle.supports('deriveBits', PBKDF2_FULL, 257)).to.equal(false);
});

const ARGON2_FULL: SubtleAlgorithm = {
  name: 'Argon2id',
  nonce: new Uint8Array(16),
  parallelism: 1,
  memory: 8,
  passes: 2,
};

test(SUITE, 'deriveBits: Argon2id length below 32 rejected', () => {
  expect(Subtle.supports('deriveBits', ARGON2_FULL, 16)).to.equal(false);
});

test(SUITE, 'deriveBits: Argon2id length 32 supported', () => {
  expect(Subtle.supports('deriveBits', ARGON2_FULL, 32)).to.equal(true);
});

// New: regression for #1025 — strict normalization rejects missing required
// dictionary members during deriveBits length validation.
test(SUITE, 'deriveBits: Argon2id missing required members rejected', () => {
  expect(Subtle.supports('deriveBits', 'Argon2id', 32)).to.equal(false);
});

// --- Invalid operation ---
test(SUITE, 'invalid operation returns false', () => {
  expect(Subtle.supports('nonexistent', 'AES-GCM')).to.equal(false);
});

// --- Invalid algorithm ---
test(SUITE, 'invalid algorithm returns false', () => {
  expect(Subtle.supports('encrypt', 'FAKE-ALGO' as never)).to.equal(false);
});
