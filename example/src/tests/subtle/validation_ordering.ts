import { expect } from 'chai';
import { subtle } from 'react-native-quick-crypto';
import type { CryptoKey, CryptoKeyPair } from 'react-native-quick-crypto';
import { test } from '../util';

// Issue #1003 — required-arg checks, validation step ordering, length=null
// handling, and getKeyLength hardening. Mirrors Node commits 856231e8c40 and
// 4cb1f284136 (lib/internal/crypto/webcrypto.js).
const SUITE = 'subtle.validation-ordering';

const subtleAny = subtle as unknown as {
  importKey: (...args: unknown[]) => Promise<CryptoKey>;
  exportKey: (...args: unknown[]) => Promise<unknown>;
  encrypt: (...args: unknown[]) => Promise<ArrayBuffer>;
  decrypt: (...args: unknown[]) => Promise<ArrayBuffer>;
  sign: (...args: unknown[]) => Promise<ArrayBuffer>;
  verify: (...args: unknown[]) => Promise<boolean>;
  generateKey: (...args: unknown[]) => Promise<CryptoKey | CryptoKeyPair>;
  deriveBits: (...args: unknown[]) => Promise<ArrayBuffer>;
  deriveKey: (...args: unknown[]) => Promise<CryptoKey>;
  wrapKey: (...args: unknown[]) => Promise<ArrayBuffer>;
  unwrapKey: (...args: unknown[]) => Promise<CryptoKey>;
  digest: (...args: unknown[]) => Promise<ArrayBuffer>;
  getPublicKey: (...args: unknown[]) => Promise<CryptoKey>;
};

async function expectThrows(
  fn: () => Promise<unknown> | unknown,
): Promise<Error> {
  let caught: unknown;
  try {
    await fn();
  } catch (e) {
    caught = e;
  }
  expect(caught, 'expected an error').to.be.instanceOf(Error);
  return caught as Error;
}

// --- B.6 required-arg count checks ----------------------------------------

test(SUITE, 'importKey throws TypeError when fewer than 5 args', async () => {
  const err = await expectThrows(() =>
    subtleAny.importKey('raw', new Uint8Array(16), { name: 'AES-GCM' }),
  );
  expect(err.name).to.equal('TypeError');
});

test(SUITE, 'generateKey throws TypeError when fewer than 3 args', async () => {
  const err = await expectThrows(() =>
    subtleAny.generateKey({ name: 'AES-GCM', length: 256 }),
  );
  expect(err.name).to.equal('TypeError');
});

test(SUITE, 'sign throws TypeError when fewer than 3 args', async () => {
  const err = await expectThrows(() =>
    subtleAny.sign({ name: 'HMAC' }, undefined),
  );
  expect(err.name).to.equal('TypeError');
});

test(SUITE, 'verify throws TypeError when fewer than 4 args', async () => {
  const err = await expectThrows(() =>
    subtleAny.verify({ name: 'HMAC' }, undefined, undefined),
  );
  expect(err.name).to.equal('TypeError');
});

test(SUITE, 'encrypt throws TypeError when fewer than 3 args', async () => {
  const err = await expectThrows(() =>
    subtleAny.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, undefined),
  );
  expect(err.name).to.equal('TypeError');
});

test(SUITE, 'decrypt throws TypeError when fewer than 3 args', async () => {
  const err = await expectThrows(() =>
    subtleAny.decrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, undefined),
  );
  expect(err.name).to.equal('TypeError');
});

test(SUITE, 'deriveBits throws TypeError when fewer than 2 args', async () => {
  const err = await expectThrows(() =>
    subtleAny.deriveBits({ name: 'PBKDF2' }),
  );
  expect(err.name).to.equal('TypeError');
});

test(SUITE, 'deriveKey throws TypeError when fewer than 5 args', async () => {
  const err = await expectThrows(() =>
    subtleAny.deriveKey(
      { name: 'PBKDF2' },
      undefined,
      { name: 'AES-GCM', length: 256 },
      true,
    ),
  );
  expect(err.name).to.equal('TypeError');
});

test(SUITE, 'wrapKey throws TypeError when fewer than 4 args', async () => {
  const err = await expectThrows(() =>
    subtleAny.wrapKey('raw', undefined, undefined),
  );
  expect(err.name).to.equal('TypeError');
});

test(SUITE, 'unwrapKey throws TypeError when fewer than 7 args', async () => {
  const err = await expectThrows(() =>
    subtleAny.unwrapKey(
      'raw',
      new Uint8Array(0),
      undefined,
      { name: 'AES-KW' },
      { name: 'AES-GCM', length: 256 },
      true,
    ),
  );
  expect(err.name).to.equal('TypeError');
});

test(SUITE, 'exportKey throws TypeError when fewer than 2 args', async () => {
  const err = await expectThrows(() => subtleAny.exportKey('raw'));
  expect(err.name).to.equal('TypeError');
});

test(SUITE, 'digest throws TypeError when fewer than 2 args', async () => {
  const err = await expectThrows(() => subtleAny.digest('SHA-256'));
  expect(err.name).to.equal('TypeError');
});

test(
  SUITE,
  'getPublicKey throws TypeError when fewer than 2 args',
  async () => {
    const err = await expectThrows(() => subtleAny.getPublicKey(undefined));
    expect(err.name).to.equal('TypeError');
  },
);

// --- B.8 validation ordering: algorithm-mismatch before usage --------------

test(
  SUITE,
  'sign with mismatched algorithm throws Key algorithm mismatch (not usage error)',
  async () => {
    // HMAC key, but ask to sign with ECDSA. Algorithm mismatch must take
    // precedence over the (also-failing) usage check.
    const key = (await subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    )) as CryptoKey;

    const err = await expectThrows(() =>
      subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new Uint8Array(8)),
    );
    expect(err.name).to.equal('InvalidAccessError');
    expect(err.message).to.contain('Key algorithm mismatch');
  },
);

test(
  SUITE,
  'sign with correct algorithm but missing usage throws usage error',
  async () => {
    const key = (await subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' },
      true,
      ['verify'],
    )) as CryptoKey;
    const err = await expectThrows(() =>
      subtle.sign({ name: 'HMAC' }, key, new Uint8Array(8)),
    );
    expect(err.name).to.equal('InvalidAccessError');
    expect(err.message.toLowerCase()).to.contain('sign');
  },
);

test(
  SUITE,
  'encrypt with mismatched algorithm throws Key algorithm mismatch first',
  async () => {
    const key = (await subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    )) as CryptoKey;
    const err = await expectThrows(() =>
      subtle.encrypt(
        { name: 'AES-CBC', iv: new Uint8Array(16) },
        key,
        new Uint8Array(16),
      ),
    );
    expect(err.name).to.equal('InvalidAccessError');
    expect(err.message).to.contain('Key algorithm mismatch');
  },
);

// --- B.9 wrapKey/unwrapKey algorithm-mismatch check ------------------------

test(
  SUITE,
  'wrapKey with mismatched wrappingKey algorithm throws Key algorithm mismatch',
  async () => {
    const key = (await subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    )) as CryptoKey;
    // wrappingKey is AES-GCM but we ask to wrap with AES-KW.
    const wrappingKey = (await subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey'],
    )) as CryptoKey;

    const err = await expectThrows(() =>
      subtle.wrapKey('raw', key, wrappingKey, { name: 'AES-KW' }),
    );
    expect(err.name).to.equal('InvalidAccessError');
    expect(err.message).to.contain('Key algorithm mismatch');
  },
);

test(
  SUITE,
  'unwrapKey with mismatched unwrappingKey algorithm throws Key algorithm mismatch',
  async () => {
    const unwrappingKey = (await subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey'],
    )) as CryptoKey;

    const err = await expectThrows(() =>
      subtle.unwrapKey(
        'raw',
        new Uint8Array(40),
        unwrappingKey,
        { name: 'AES-KW' },
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt'],
      ),
    );
    expect(err.name).to.equal('InvalidAccessError');
    expect(err.message).to.contain('Key algorithm mismatch');
  },
);

// --- B.10 deriveBits length=null handling ---------------------------------

test(
  SUITE,
  'deriveBits ECDH with length=null returns full shared secret',
  async () => {
    const alice = (await subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    )) as CryptoKeyPair;
    const bob = (await subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    )) as CryptoKeyPair;

    const full = await subtle.deriveBits(
      { name: 'ECDH', public: bob.publicKey } as unknown as {
        name: 'ECDH';
        public: CryptoKey;
      },
      alice.privateKey as CryptoKey,
      null as unknown as number,
    );
    // P-256 shared secret is 32 bytes
    expect(full.byteLength).to.equal(32);
  },
);

test(
  SUITE,
  'deriveBits with length omitted defaults to null (full secret)',
  async () => {
    const alice = (await subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    )) as CryptoKeyPair;
    const bob = (await subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    )) as CryptoKeyPair;

    const full = await subtleAny.deriveBits(
      { name: 'ECDH', public: bob.publicKey },
      alice.privateKey as CryptoKey,
    );
    expect((full as ArrayBuffer).byteLength).to.equal(32);
  },
);

test(
  SUITE,
  'deriveBits HKDF with length=null throws OperationError',
  async () => {
    const baseKey = await subtle.importKey(
      'raw',
      new Uint8Array(32),
      { name: 'HKDF' },
      false,
      ['deriveBits'],
    );

    const err = await expectThrows(() =>
      subtleAny.deriveBits(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt: new Uint8Array(0),
          info: new Uint8Array(0),
        },
        baseKey,
        null,
      ),
    );
    expect(err.name).to.equal('OperationError');
    expect(err.message.toLowerCase()).to.contain('null');
  },
);

test(
  SUITE,
  'deriveBits PBKDF2 with length=null throws OperationError',
  async () => {
    const baseKey = await subtle.importKey(
      'raw',
      new TextEncoder().encode('password'),
      { name: 'PBKDF2' },
      false,
      ['deriveBits'],
    );

    const err = await expectThrows(() =>
      subtleAny.deriveBits(
        {
          name: 'PBKDF2',
          hash: 'SHA-256',
          salt: new Uint8Array(8),
          iterations: 1000,
        },
        baseKey,
        null,
      ),
    );
    expect(err.name).to.equal('OperationError');
    expect(err.message.toLowerCase()).to.contain('null');
  },
);

// --- B.11 getKeyLength validation -----------------------------------------

test(
  SUITE,
  'deriveKey to AES-GCM with invalid length throws OperationError',
  async () => {
    const baseKey = await subtle.importKey(
      'raw',
      new TextEncoder().encode('password'),
      { name: 'PBKDF2' },
      false,
      ['deriveKey'],
    );
    const err = await expectThrows(() =>
      subtle.deriveKey(
        {
          name: 'PBKDF2',
          hash: 'SHA-256',
          salt: new Uint8Array(8),
          iterations: 1000,
        },
        baseKey,
        // 100 is not a valid AES key length
        { name: 'AES-GCM', length: 100 } as unknown as { name: 'AES-GCM' },
        true,
        ['encrypt', 'decrypt'],
      ),
    );
    expect(err.name).to.equal('OperationError');
    expect(err.message).to.contain('Invalid key length');
  },
);

test(
  SUITE,
  'deriveKey to HMAC with length=0 throws OperationError',
  async () => {
    const baseKey = await subtle.importKey(
      'raw',
      new TextEncoder().encode('password'),
      { name: 'PBKDF2' },
      false,
      ['deriveKey'],
    );
    const err = await expectThrows(() =>
      subtle.deriveKey(
        {
          name: 'PBKDF2',
          hash: 'SHA-256',
          salt: new Uint8Array(8),
          iterations: 1000,
        },
        baseKey,
        { name: 'HMAC', hash: 'SHA-256', length: 0 } as unknown as {
          name: 'HMAC';
        },
        true,
        ['sign', 'verify'],
      ),
    );
    expect(err.name).to.equal('OperationError');
    expect(err.message).to.contain('Invalid key length');
  },
);
