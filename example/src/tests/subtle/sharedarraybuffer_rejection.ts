import { expect } from 'chai';
import crypto, { subtle, getRandomValues } from 'react-native-quick-crypto';
import type { CryptoKey, HkdfAlgorithm } from 'react-native-quick-crypto';
import { test } from '../util';

// WebCrypto / Web IDL §BufferSource: SharedArrayBuffer-backed inputs must
// be rejected from all subtle.* methods and getRandomValues. Concurrent
// writes during async crypto operations can race with the algorithm,
// corrupting output or leaking intermediate state.
//
// Reference: Node.js commit bee10872588 ("lib: reject SharedArrayBuffer in
// web APIs per spec") — Node throws TypeError, matching the WebIDL
// BufferSource converter and the W3C WebCrypto spec.

const SUITE = 'subtle.sharedarraybuffer-rejection';

// Some hosts (older Hermes builds) don't expose SharedArrayBuffer at all.
// Skip the suite cleanly in that case rather than failing.
const sabAvailable = typeof SharedArrayBuffer !== 'undefined';

function makeSab(byteLength = 16): SharedArrayBuffer {
  return new SharedArrayBuffer(byteLength);
}

function makeSabView(byteLength = 16): Uint8Array {
  return new Uint8Array(makeSab(byteLength));
}

function expectRejected(err: unknown, label: string) {
  expect(err, `${label}: expected an error`).to.be.instanceOf(Error);
  // WebIDL BufferSource conversion failure is TypeError per spec / Node.
  expect((err as Error).name, `${label}: error name`).to.equal('TypeError');
  expect(
    (err as Error).message.toLowerCase(),
    `${label}: error message mentions SharedArrayBuffer`,
  ).to.include('sharedarraybuffer');
}

if (sabAvailable) {
  // ---- getRandomValues ----------------------------------------------------

  test(SUITE, 'getRandomValues rejects SAB-backed Uint8Array', () => {
    let caught: unknown;
    try {
      getRandomValues(makeSabView(8));
    } catch (e) {
      caught = e;
    }
    expectRejected(caught, 'getRandomValues');
  });

  // ---- randomFill / randomFillSync ---------------------------------------

  test(SUITE, 'randomFillSync rejects SAB-backed Uint8Array', () => {
    let caught: unknown;
    try {
      crypto.randomFillSync(makeSabView(8));
    } catch (e) {
      caught = e;
    }
    expectRejected(caught, 'randomFillSync');
  });

  test(SUITE, 'randomFillSync rejects raw SharedArrayBuffer', () => {
    let caught: unknown;
    try {
      crypto.randomFillSync(makeSab(8) as unknown as ArrayBuffer);
    } catch (e) {
      caught = e;
    }
    expectRejected(caught, 'randomFillSync (raw SAB)');
  });

  test(SUITE, 'randomFill rejects SAB-backed Uint8Array', () => {
    let caught: unknown;
    try {
      crypto.randomFill(makeSabView(8), () => {
        // not reached
      });
    } catch (e) {
      caught = e;
    }
    expectRejected(caught, 'randomFill');
  });

  // ---- subtle.digest -----------------------------------------------------

  test(SUITE, 'subtle.digest rejects SAB-backed view', async () => {
    let caught: unknown;
    try {
      await subtle.digest('SHA-256', makeSabView(8));
    } catch (e) {
      caught = e;
    }
    expectRejected(caught, 'subtle.digest');
  });

  test(SUITE, 'subtle.digest rejects raw SharedArrayBuffer', async () => {
    let caught: unknown;
    try {
      await subtle.digest('SHA-256', makeSab(8) as unknown as ArrayBuffer);
    } catch (e) {
      caught = e;
    }
    expectRejected(caught, 'subtle.digest (raw SAB)');
  });

  // ---- subtle.encrypt / decrypt ------------------------------------------

  test(SUITE, 'subtle.encrypt rejects SAB-backed plaintext', async () => {
    const key = await subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    const iv = new Uint8Array(12);
    let caught: unknown;
    try {
      await subtle.encrypt(
        { name: 'AES-GCM', iv },
        key as CryptoKey,
        makeSabView(16),
      );
    } catch (e) {
      caught = e;
    }
    expectRejected(caught, 'subtle.encrypt');
  });

  test(SUITE, 'subtle.encrypt rejects SAB-backed iv', async () => {
    const key = await subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    let caught: unknown;
    try {
      await subtle.encrypt(
        { name: 'AES-GCM', iv: makeSabView(12) },
        key as CryptoKey,
        new Uint8Array(16),
      );
    } catch (e) {
      caught = e;
    }
    expectRejected(caught, 'subtle.encrypt (SAB iv)');
  });

  test(SUITE, 'subtle.decrypt rejects SAB-backed ciphertext', async () => {
    const key = await subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    let caught: unknown;
    try {
      await subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(12) },
        key as CryptoKey,
        makeSabView(32),
      );
    } catch (e) {
      caught = e;
    }
    expectRejected(caught, 'subtle.decrypt');
  });

  // ---- subtle.sign / verify ---------------------------------------------

  test(SUITE, 'subtle.sign rejects SAB-backed data', async () => {
    const key = await subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify'],
    );
    let caught: unknown;
    try {
      await subtle.sign({ name: 'HMAC' }, key as CryptoKey, makeSabView(16));
    } catch (e) {
      caught = e;
    }
    expectRejected(caught, 'subtle.sign');
  });

  test(SUITE, 'subtle.verify rejects SAB-backed signature', async () => {
    const key = await subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify'],
    );
    let caught: unknown;
    try {
      await subtle.verify(
        { name: 'HMAC' },
        key as CryptoKey,
        makeSabView(32),
        new Uint8Array(16),
      );
    } catch (e) {
      caught = e;
    }
    expectRejected(caught, 'subtle.verify (SAB signature)');
  });

  test(SUITE, 'subtle.verify rejects SAB-backed data', async () => {
    const key = await subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify'],
    );
    let caught: unknown;
    try {
      await subtle.verify(
        { name: 'HMAC' },
        key as CryptoKey,
        new Uint8Array(32),
        makeSabView(16),
      );
    } catch (e) {
      caught = e;
    }
    expectRejected(caught, 'subtle.verify (SAB data)');
  });

  // ---- subtle.importKey --------------------------------------------------

  test(SUITE, 'subtle.importKey rejects SAB-backed raw key', async () => {
    let caught: unknown;
    try {
      await subtle.importKey(
        'raw',
        makeSabView(32),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
      );
    } catch (e) {
      caught = e;
    }
    expectRejected(caught, 'subtle.importKey');
  });

  // ---- subtle.encrypt AES-GCM additionalData ----------------------------

  test(
    SUITE,
    'subtle.encrypt AES-GCM rejects SAB-backed additionalData',
    async () => {
      const key = await subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
      );
      let caught: unknown;
      try {
        await subtle.encrypt(
          {
            name: 'AES-GCM',
            iv: new Uint8Array(12),
            additionalData: makeSabView(16),
          },
          key as CryptoKey,
          new Uint8Array(16),
        );
      } catch (e) {
        caught = e;
      }
      expectRejected(caught, 'subtle.encrypt (SAB additionalData)');
    },
  );

  // ---- subtle.encrypt AES-CTR counter -----------------------------------

  test(SUITE, 'subtle.encrypt AES-CTR rejects SAB-backed counter', async () => {
    const key = await subtle.generateKey(
      { name: 'AES-CTR', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    let caught: unknown;
    try {
      await subtle.encrypt(
        { name: 'AES-CTR', counter: makeSabView(16), length: 64 },
        key as CryptoKey,
        new Uint8Array(16),
      );
    } catch (e) {
      caught = e;
    }
    expectRejected(caught, 'subtle.encrypt (SAB counter)');
  });

  // ---- subtle.deriveBits (HKDF salt/info) --------------------------------

  test(SUITE, 'subtle.deriveBits rejects SAB-backed HKDF salt', async () => {
    const baseKey = await subtle.importKey(
      'raw',
      new Uint8Array(32),
      'HKDF',
      false,
      ['deriveBits'],
    );
    let caught: unknown;
    try {
      const algorithm = {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: makeSabView(16),
        info: new Uint8Array(0),
      } satisfies HkdfAlgorithm;
      await subtle.deriveBits(
        algorithm as Parameters<typeof subtle.deriveBits>[0],
        baseKey,
        128,
      );
    } catch (e) {
      caught = e;
    }
    expectRejected(caught, 'subtle.deriveBits (SAB salt)');
  });
}
