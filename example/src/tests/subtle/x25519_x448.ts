import { expect } from 'chai';
import {
  subtle,
  type CryptoKeyPair,
  type CryptoKey,
} from 'react-native-quick-crypto';
import { test } from '../util';

const SUITE = 'subtle x25519/x448';

test(
  SUITE,
  'X25519 - generateKey, exportKey, importKey, deriveBits',
  async () => {
    const format = 'raw';
    const algorithm = { name: 'X25519' } as const;

    // 1. Generate Keys
    const aliceKeys = (await subtle.generateKey(algorithm, true, [
      'deriveKey',
      'deriveBits',
    ])) as CryptoKeyPair;

    const bobKeys = (await subtle.generateKey(algorithm, true, [
      'deriveKey',
      'deriveBits',
    ])) as CryptoKeyPair;

    expect((aliceKeys.publicKey as CryptoKey).algorithm.name).to.equal(
      'X25519',
    );
    expect((aliceKeys.privateKey as CryptoKey).algorithm.name).to.equal(
      'X25519',
    );

    // 2. Export Keys
    const alicePubRaw = await subtle.exportKey(
      format,
      aliceKeys.publicKey as CryptoKey,
    );
    const bobPubRaw = await subtle.exportKey(
      format,
      bobKeys.publicKey as CryptoKey,
    );

    // 3. Import Keys
    const alicePubImported = await subtle.importKey(
      format,
      alicePubRaw,
      algorithm,
      true,
      [],
    );

    const bobPubImported = await subtle.importKey(
      format,
      bobPubRaw,
      algorithm,
      true,
      [],
    );

    // 4. Derive Bits
    const bitsLength = 256;
    const aliceShared = await subtle.deriveBits(
      { name: 'X25519', public: bobPubImported } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
      aliceKeys.privateKey as CryptoKey,
      bitsLength,
    );

    const bobShared = await subtle.deriveBits(
      { name: 'X25519', public: alicePubImported } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
      bobKeys.privateKey as CryptoKey,
      bitsLength,
    );

    // Verify shared secrets match
    const aliceSharedView = new Uint8Array(aliceShared);
    const bobSharedView = new Uint8Array(bobShared);

    expect(aliceSharedView.length).to.equal(bitsLength / 8);
    expect(aliceSharedView).to.deep.equal(bobSharedView);
  },
);

test(
  SUITE,
  'X448 - generateKey, exportKey, importKey, deriveBits',
  async () => {
    const format = 'spki'; // Use SPKI for X448 public key export test
    const algorithm = { name: 'X448' } as const;

    // 1. Generate Keys
    const aliceKeys = (await subtle.generateKey(algorithm, true, [
      'deriveKey',
      'deriveBits',
    ])) as CryptoKeyPair;

    const bobKeys = (await subtle.generateKey(algorithm, true, [
      'deriveKey',
      'deriveBits',
    ])) as CryptoKeyPair;

    expect((aliceKeys.publicKey as CryptoKey).algorithm.name).to.equal('X448');
    expect((aliceKeys.privateKey as CryptoKey).algorithm.name).to.equal('X448');

    // 2. Export Keys
    const alicePubSpki = await subtle.exportKey(
      format,
      aliceKeys.publicKey as CryptoKey,
    );
    const bobPubSpki = await subtle.exportKey(
      format,
      bobKeys.publicKey as CryptoKey,
    );

    // 3. Import Keys
    const alicePubImported = await subtle.importKey(
      format,
      alicePubSpki,
      algorithm,
      true,
      [],
    );

    const bobPubImported = await subtle.importKey(
      format,
      bobPubSpki,
      algorithm,
      true,
      [],
    );

    // 4. Derive Bits
    const bitsLength = 448; // X448 produces 56 bytes
    const aliceShared = await subtle.deriveBits(
      { name: 'X448', public: bobPubImported } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
      aliceKeys.privateKey as CryptoKey,
      bitsLength,
    );

    const bobShared = await subtle.deriveBits(
      { name: 'X448', public: alicePubImported } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
      bobKeys.privateKey as CryptoKey,
      bitsLength,
    );

    // Verify shared secrets match
    const aliceSharedView = new Uint8Array(aliceShared);
    const bobSharedView = new Uint8Array(bobShared);

    expect(aliceSharedView.length).to.equal(56);
    expect(aliceSharedView).to.deep.equal(bobSharedView);
  },
);
