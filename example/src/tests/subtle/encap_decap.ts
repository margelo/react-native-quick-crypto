import { expect } from 'chai';
import { test } from '../util';
import crypto from 'react-native-quick-crypto';
import type { WebCryptoKeyPair } from 'react-native-quick-crypto';

const { subtle } = crypto;

const SUITE = 'subtle.encapsulate/decapsulate';

type MlKemVariant = 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024';
const MLKEM_VARIANTS: MlKemVariant[] = [
  'ML-KEM-512',
  'ML-KEM-768',
  'ML-KEM-1024',
];

const MLKEM_CIPHERTEXT_SIZES: Record<MlKemVariant, number> = {
  'ML-KEM-512': 768,
  'ML-KEM-768': 1088,
  'ML-KEM-1024': 1568,
};

const SHARED_SECRET_SIZE = 32;

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
