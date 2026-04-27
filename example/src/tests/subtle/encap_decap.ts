import { expect } from 'chai';
import { test } from '../util';
import crypto from 'react-native-quick-crypto';
import type { WebCryptoKeyPair } from 'react-native-quick-crypto';
import {
  MLKEM_VARIANTS,
  MLKEM_CIPHERTEXT_SIZES,
  SHARED_SECRET_SIZE,
} from './mlkem_constants';

const { subtle } = crypto;

const SUITE = 'subtle.encapsulate/decapsulate';

// --- encapsulateBits / decapsulateBits ---

for (const variant of MLKEM_VARIANTS) {
  test(SUITE, `${variant} encapsulateBits/decapsulateBits`, async () => {
    const keyPair = await subtle.generateKey({ name: variant }, true, [
      'encapsulateBits',
      'decapsulateBits',
    ]);

    const { publicKey, privateKey } = keyPair as WebCryptoKeyPair;

    const { sharedKey, ciphertext } = await subtle.encapsulateBits(
      { name: variant },
      publicKey,
    );

    expect(ciphertext.byteLength).to.equal(MLKEM_CIPHERTEXT_SIZES[variant]);
    expect(sharedKey.byteLength).to.equal(SHARED_SECRET_SIZE);

    const decapsulated = await subtle.decapsulateBits(
      { name: variant },
      privateKey,
      ciphertext,
    );

    expect(decapsulated.byteLength).to.equal(SHARED_SECRET_SIZE);

    const encapsulatedBytes = new Uint8Array(sharedKey);
    const decapsulatedBytes = new Uint8Array(decapsulated);
    expect(encapsulatedBytes).to.deep.equal(decapsulatedBytes);
  });

  // --- encapsulateKey / decapsulateKey with AES-GCM ---

  test(SUITE, `${variant} encapsulateKey/decapsulateKey AES-GCM`, async () => {
    const keyPair = await subtle.generateKey({ name: variant }, true, [
      'encapsulateKey',
      'decapsulateKey',
    ]);

    const { publicKey, privateKey } = keyPair as WebCryptoKeyPair;

    const { key: aesKey, ciphertext } = await subtle.encapsulateKey(
      { name: variant },
      publicKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );

    expect(ciphertext.byteLength).to.equal(MLKEM_CIPHERTEXT_SIZES[variant]);
    expect(aesKey.algorithm.name).to.equal('AES-GCM');
    expect(aesKey.extractable).to.equal(true);
    expect(aesKey.usages).to.include('encrypt');

    const decapsulatedKey = await subtle.decapsulateKey(
      { name: variant },
      privateKey,
      ciphertext,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );

    expect(decapsulatedKey.algorithm.name).to.equal('AES-GCM');

    const rawEncapsulated = await subtle.exportKey('raw', aesKey);
    const rawDecapsulated = await subtle.exportKey('raw', decapsulatedKey);
    expect(new Uint8Array(rawEncapsulated as ArrayBuffer)).to.deep.equal(
      new Uint8Array(rawDecapsulated as ArrayBuffer),
    );
  });

  // --- Import then encapsulate/decapsulate roundtrip ---

  test(SUITE, `${variant} import then encap/decap`, async () => {
    const keyPair = await subtle.generateKey({ name: variant }, true, [
      'encapsulateBits',
      'decapsulateBits',
    ]);

    const { publicKey, privateKey } = keyPair as WebCryptoKeyPair;

    const spki = (await subtle.exportKey('spki', publicKey)) as ArrayBuffer;
    const pkcs8 = (await subtle.exportKey('pkcs8', privateKey)) as ArrayBuffer;

    const importedPub = await subtle.importKey(
      'spki',
      spki,
      { name: variant },
      true,
      ['encapsulateBits'],
    );
    const importedPriv = await subtle.importKey(
      'pkcs8',
      pkcs8,
      { name: variant },
      true,
      ['decapsulateBits'],
    );

    const { sharedKey, ciphertext } = await subtle.encapsulateBits(
      { name: variant },
      importedPub,
    );

    const decapsulated = await subtle.decapsulateBits(
      { name: variant },
      importedPriv,
      ciphertext,
    );

    expect(new Uint8Array(sharedKey)).to.deep.equal(
      new Uint8Array(decapsulated),
    );
  });
}

// --- Top-level crypto.encapsulate/decapsulate ---

for (const variant of MLKEM_VARIANTS) {
  test(SUITE, `${variant} crypto.encapsulate/decapsulate`, async () => {
    const keyPair = await subtle.generateKey({ name: variant }, true, [
      'encapsulateBits',
      'decapsulateBits',
    ]);

    const { publicKey, privateKey } = keyPair as WebCryptoKeyPair;

    const result = crypto.encapsulate(publicKey);
    expect(result).to.have.property('sharedKey');
    expect(result).to.have.property('ciphertext');

    const { sharedKey, ciphertext } = result!;
    expect(ciphertext.byteLength).to.equal(MLKEM_CIPHERTEXT_SIZES[variant]);
    expect(sharedKey.byteLength).to.equal(SHARED_SECRET_SIZE);

    const decapsulated = crypto.decapsulate(privateKey, ciphertext);
    expect(decapsulated).to.be.an.instanceOf(ArrayBuffer);
    expect((decapsulated as ArrayBuffer).byteLength).to.equal(
      SHARED_SECRET_SIZE,
    );

    expect(new Uint8Array(sharedKey)).to.deep.equal(
      new Uint8Array(decapsulated as ArrayBuffer),
    );
  });
}

// --- Phase 4.1: ML-KEM NIST-style robustness checks ---
//
// FIPS 203 mandates *implicit rejection*: when decapsulation receives a
// ciphertext that the private key cannot validly decapsulate (corrupted
// bytes, or originated from a different public key), it MUST NOT throw
// and MUST NOT signal failure — instead it returns a deterministic but
// pseudorandom shared secret derived from the secret hash z and the input
// ciphertext. This prevents Bleichenbacher-style oracles. The checks
// below pin both observable properties:
//
//   (a) decapsulateBits with a tampered ciphertext returns 32 bytes (not
//       an error), and those bytes differ from the encapsulator's shared
//       key — i.e. the tamper is *detected* (different output) without
//       being announced (no exception).
//   (b) decapsulateBits with a wrong-keypair private key likewise returns
//       32 deterministic-but-different bytes.
//   (c) Cross-variant: encap with ML-KEM-768 pub, decap with ML-KEM-512
//       priv must reject (different ciphertext sizes — the spec mandates
//       size validation before implicit rejection kicks in).

for (const variant of MLKEM_VARIANTS) {
  test(
    SUITE,
    `${variant} implicit rejection on tampered ciphertext`,
    async () => {
      const kp = (await subtle.generateKey({ name: variant }, true, [
        'encapsulateBits',
        'decapsulateBits',
      ])) as WebCryptoKeyPair;

      const { sharedKey, ciphertext } = await subtle.encapsulateBits(
        { name: variant },
        kp.publicKey,
      );

      // Flip the last byte of the ciphertext — must not throw, must yield
      // a 32-byte shared secret different from the original.
      const tampered = new Uint8Array(ciphertext);
      tampered[tampered.length - 1] =
        (tampered[tampered.length - 1] ?? 0) ^ 0xff;

      const decapsulated = await subtle.decapsulateBits(
        { name: variant },
        kp.privateKey,
        tampered.buffer,
      );

      expect(decapsulated.byteLength).to.equal(SHARED_SECRET_SIZE);
      const original = new Uint8Array(sharedKey);
      const derived = new Uint8Array(decapsulated);
      // The two must differ. (Probability of accidental equality is ~2^-256.)
      let allEqual = true;
      for (let i = 0; i < original.length; i++) {
        if (original[i] !== derived[i]) {
          allEqual = false;
          break;
        }
      }
      expect(allEqual).to.equal(false);
    },
  );

  test(
    SUITE,
    `${variant} implicit rejection with wrong private key`,
    async () => {
      const kp1 = (await subtle.generateKey({ name: variant }, true, [
        'encapsulateBits',
        'decapsulateBits',
      ])) as WebCryptoKeyPair;
      const kp2 = (await subtle.generateKey({ name: variant }, true, [
        'encapsulateBits',
        'decapsulateBits',
      ])) as WebCryptoKeyPair;

      const { sharedKey, ciphertext } = await subtle.encapsulateBits(
        { name: variant },
        kp1.publicKey,
      );

      // Decap with kp2.privateKey (wrong key) — implicit rejection: must
      // return 32 bytes deterministically, not equal to the encap shared key.
      const decapsulated = await subtle.decapsulateBits(
        { name: variant },
        kp2.privateKey,
        ciphertext,
      );
      expect(decapsulated.byteLength).to.equal(SHARED_SECRET_SIZE);
      const original = new Uint8Array(sharedKey);
      const derived = new Uint8Array(decapsulated);
      let allEqual = true;
      for (let i = 0; i < original.length; i++) {
        if (original[i] !== derived[i]) {
          allEqual = false;
          break;
        }
      }
      expect(allEqual).to.equal(false);
    },
  );
}

// Cross-variant rejection: ML-KEM-768 ciphertexts have 1088 bytes, while
// ML-KEM-512 expects 768. Decap'ing a 768-variant ciphertext with a
// 512-variant private key must fail — either by exception or by silently
// producing a random secret without the implicit-rejection guarantee. We
// expect an error here because the size check happens before any KEM op.
test(
  SUITE,
  'ML-KEM cross-variant: 768 ciphertext into 512 priv rejected',
  async () => {
    const kp512 = (await subtle.generateKey({ name: 'ML-KEM-512' }, true, [
      'encapsulateBits',
      'decapsulateBits',
    ])) as WebCryptoKeyPair;
    const kp768 = (await subtle.generateKey({ name: 'ML-KEM-768' }, true, [
      'encapsulateBits',
      'decapsulateBits',
    ])) as WebCryptoKeyPair;

    const { ciphertext } = await subtle.encapsulateBits(
      { name: 'ML-KEM-768' },
      kp768.publicKey,
    );

    let threw = false;
    try {
      await subtle.decapsulateBits(
        { name: 'ML-KEM-512' },
        kp512.privateKey,
        ciphertext,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  },
);
