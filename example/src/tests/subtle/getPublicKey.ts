import { expect } from 'chai';
import { subtle, Buffer, CryptoKey } from 'react-native-quick-crypto';
import { assertThrowsAsync, test } from '../util';

const SUITE = 'subtle.getPublicKey';

type RnqcCryptoKey = InstanceType<typeof CryptoKey>;
type KeyPair = { privateKey: RnqcCryptoKey; publicKey: RnqcCryptoKey };

test(SUITE, 'Ed25519: derive public from private', async () => {
  const keyPair = (await subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as KeyPair;

  const derived = await subtle.getPublicKey(keyPair.privateKey, ['verify']);

  expect(derived.type).to.equal('public');
  expect(derived.algorithm.name).to.equal('Ed25519');
  expect(derived.extractable).to.equal(true);
  expect(derived.usages).to.include('verify');

  const originalExport = await subtle.exportKey('raw', keyPair.publicKey);
  const derivedExport = await subtle.exportKey('raw', derived);
  expect(Buffer.from(derivedExport as ArrayBuffer).toString('hex')).to.equal(
    Buffer.from(originalExport as ArrayBuffer).toString('hex'),
  );
});

test(SUITE, 'Ed448: derive public from private', async () => {
  const keyPair = (await subtle.generateKey({ name: 'Ed448' }, true, [
    'sign',
    'verify',
  ])) as KeyPair;

  const derived = await subtle.getPublicKey(keyPair.privateKey, ['verify']);

  expect(derived.type).to.equal('public');
  expect(derived.algorithm.name).to.equal('Ed448');

  const originalExport = await subtle.exportKey('raw', keyPair.publicKey);
  const derivedExport = await subtle.exportKey('raw', derived);
  expect(Buffer.from(derivedExport as ArrayBuffer).toString('hex')).to.equal(
    Buffer.from(originalExport as ArrayBuffer).toString('hex'),
  );
});

test(SUITE, 'ECDSA P-256: derive public from private', async () => {
  const keyPair = (await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as KeyPair;

  const derived = await subtle.getPublicKey(keyPair.privateKey, ['verify']);

  expect(derived.type).to.equal('public');
  expect(derived.algorithm.name).to.equal('ECDSA');

  const originalExport = await subtle.exportKey('spki', keyPair.publicKey);
  const derivedExport = await subtle.exportKey('spki', derived);
  expect(Buffer.from(derivedExport as ArrayBuffer).toString('hex')).to.equal(
    Buffer.from(originalExport as ArrayBuffer).toString('hex'),
  );
});

test(SUITE, 'RSA-PSS: derive public from private', async () => {
  const keyPair = (await subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )) as KeyPair;

  const derived = await subtle.getPublicKey(keyPair.privateKey, ['verify']);

  expect(derived.type).to.equal('public');
  expect(derived.algorithm.name).to.equal('RSA-PSS');

  const originalExport = await subtle.exportKey('spki', keyPair.publicKey);
  const derivedExport = await subtle.exportKey('spki', derived);
  expect(Buffer.from(derivedExport as ArrayBuffer).toString('hex')).to.equal(
    Buffer.from(originalExport as ArrayBuffer).toString('hex'),
  );
});

test(
  SUITE,
  'X25519: derive public from private for key agreement',
  async () => {
    const keyPair = (await subtle.generateKey({ name: 'X25519' }, true, [
      'deriveKey',
      'deriveBits',
    ])) as KeyPair;

    const derived = await subtle.getPublicKey(keyPair.privateKey, []);

    expect(derived.type).to.equal('public');
    expect(derived.algorithm.name).to.equal('X25519');

    const originalExport = await subtle.exportKey('raw', keyPair.publicKey);
    const derivedExport = await subtle.exportKey('raw', derived);
    expect(Buffer.from(derivedExport as ArrayBuffer).toString('hex')).to.equal(
      Buffer.from(originalExport as ArrayBuffer).toString('hex'),
    );
  },
);

test(SUITE, 'Error: passing public key throws InvalidAccessError', async () => {
  const keyPair = (await subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as KeyPair;

  await assertThrowsAsync(
    async () => subtle.getPublicKey(keyPair.publicKey, ['verify']),
    'key must be a private key',
  );
});

test(SUITE, 'Error: passing secret key throws NotSupportedError', async () => {
  const secretKey = await subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  await assertThrowsAsync(
    async () => subtle.getPublicKey(secretKey as unknown as RnqcCryptoKey, []),
    'key must be a private key',
  );
});
