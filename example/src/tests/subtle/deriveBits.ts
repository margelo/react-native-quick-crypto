import { expect } from 'chai';
import crypto, {
  Buffer,
  subtle,
  ab2str,
  type HashAlgorithm,
  normalizeHashName,
  KeyObject,
} from 'react-native-quick-crypto';
import { test } from '../util';

type TestFixture = [
  string,
  string,
  number,
  HashAlgorithm | string,
  number,
  string,
];

const SUITE = 'subtle.deriveBits';

// pbkdf2 deriveBits()
// {
const test_fn = async (
  pass: string,
  salt: string,
  iterations: number,
  hash: HashAlgorithm | string,
  length: number,
  expected: string,
) => {
  const key = await subtle.importKey(
    'raw',
    pass,
    { name: 'PBKDF2', hash: normalizeHashName(hash) },
    false,
    ['deriveBits'],
  );

  const bits = await subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: normalizeHashName(hash),
    },
    key,
    length,
  );
  expect(ab2str(bits)).to.equal(expected);
};

const kTests: TestFixture[] = [
  [
    'hello',
    'there',
    10,
    'SHA-256',
    512,
    'f72d1cf4853fffbd16a42751765d11f8dc7939498ee7b7' +
      'ce7678b4cb16fad88098110a83e71f4483ce73203f7a64' +
      '719d293280f780f9fafdcf46925c5c0588b3',
  ],
  ['hello', 'there', 5, 'SHA-384', 128, '201509b012c9cd2fbe7ea938f0c509b3'],
];

kTests.forEach(async ([pass, salt, iterations, hash, length, expected]) => {
  test(
    SUITE,
    `PBKDF2 importKey raw/deriveBits - ${pass} ${salt} ${iterations} ${hash} ${length}`,
    async () => {
      await test_fn(pass, salt, iterations, hash, length, expected);
    },
  );
});

// --- X25519 deriveBits Tests (from cfrg suite) ---

test(SUITE, 'x25519 - shared secret', () => {
  const alice = crypto.generateKeyPairSync('x25519', {});
  const bob = crypto.generateKeyPairSync('x25519', {});

  if (!alice.privateKey || !(alice.privateKey instanceof ArrayBuffer)) {
    throw new Error('Failed to generate private key for Alice');
  }
  if (!bob.publicKey || !(bob.publicKey instanceof ArrayBuffer)) {
    throw new Error('Failed to generate public key for Bob');
  }

  const privateKey = KeyObject.createKeyObject('private', alice.privateKey);
  const publicKey = KeyObject.createKeyObject('public', bob.publicKey);

  const sharedSecret = crypto.diffieHellman({
    privateKey,
    publicKey,
  });
  expect(Buffer.isBuffer(sharedSecret)).to.equal(true);
});

test(SUITE, 'x25519 - shared secret symmetry', () => {
  const alice = crypto.generateKeyPairSync('x25519', {});
  const bob = crypto.generateKeyPairSync('x25519', {});

  const alicePrivate = KeyObject.createKeyObject(
    'private',
    alice.privateKey as ArrayBuffer,
  );
  const alicePublic = KeyObject.createKeyObject(
    'public',
    alice.publicKey as ArrayBuffer,
  );
  const bobPrivate = KeyObject.createKeyObject(
    'private',
    bob.privateKey as ArrayBuffer,
  );
  const bobPublic = KeyObject.createKeyObject(
    'public',
    bob.publicKey as ArrayBuffer,
  );

  const sharedSecretAlice = crypto.diffieHellman({
    privateKey: alicePrivate,
    publicKey: bobPublic,
  }) as Buffer;

  const sharedSecretBob = crypto.diffieHellman({
    privateKey: bobPrivate,
    publicKey: alicePublic,
  }) as Buffer;

  expect(Buffer.isBuffer(sharedSecretAlice)).to.equal(true);
  expect(Buffer.isBuffer(sharedSecretBob)).to.equal(true);
  expect(sharedSecretAlice.equals(sharedSecretBob)).to.equal(true);
});

test(SUITE, 'x25519 - shared secret properties', () => {
  const alice = crypto.generateKeyPairSync('x25519', {});
  const bob = crypto.generateKeyPairSync('x25519', {});

  const alicePrivate = KeyObject.createKeyObject(
    'private',
    alice.privateKey as ArrayBuffer,
  );
  const bobPublic = KeyObject.createKeyObject(
    'public',
    bob.publicKey as ArrayBuffer,
  );

  const sharedSecret = crypto.diffieHellman({
    privateKey: alicePrivate,
    publicKey: bobPublic,
  }) as Buffer;

  expect(sharedSecret.length).to.equal(32);

  const allZeros = Buffer.alloc(32, 0);
  expect(sharedSecret.equals(allZeros)).to.equal(false);

  const sharedSecret2 = crypto.diffieHellman({
    privateKey: alicePrivate,
    publicKey: bobPublic,
  }) as Buffer;
  expect(sharedSecret.equals(sharedSecret2)).to.equal(true);
});

test(SUITE, 'x25519 - different key pairs produce different secrets', () => {
  const alice = crypto.generateKeyPairSync('x25519', {});
  const bob = crypto.generateKeyPairSync('x25519', {});
  const charlie = crypto.generateKeyPairSync('x25519', {});

  const alicePrivate = KeyObject.createKeyObject(
    'private',
    alice.privateKey as ArrayBuffer,
  );
  const bobPublic = KeyObject.createKeyObject(
    'public',
    bob.publicKey as ArrayBuffer,
  );
  const charliePublic = KeyObject.createKeyObject(
    'public',
    charlie.publicKey as ArrayBuffer,
  );

  const secretAliceBob = crypto.diffieHellman({
    privateKey: alicePrivate,
    publicKey: bobPublic,
  }) as Buffer;

  const secretAliceCharlie = crypto.diffieHellman({
    privateKey: alicePrivate,
    publicKey: charliePublic,
  }) as Buffer;

  expect(secretAliceBob.equals(secretAliceCharlie)).to.equal(false);
});

test(SUITE, 'x25519 - error handling', () => {
  const alice = crypto.generateKeyPairSync('x25519', {});

  const alicePrivate = KeyObject.createKeyObject(
    'private',
    alice.privateKey as ArrayBuffer,
  );

  expect(() => {
    KeyObject.createKeyObject('public', new ArrayBuffer(16));
  }).to.throw();

  expect(() => {
    crypto.diffieHellman({
      privateKey: alicePrivate,
      publicKey: {} as KeyObject,
    });
  }).to.throw();
});

// ecdh deriveBits
