import { expect } from 'chai';
import { Buffer } from '@craftzdog/react-native-buffer';
import crypto, { KeyObject } from 'react-native-quick-crypto';
import { test } from '../util';

const SUITE = 'cfrg';

test(SUITE, 'x25519 - shared secret', () => {
  // Generate key pairs
  const alice = crypto.generateKeyPairSync('x25519', {});
  const bob = crypto.generateKeyPairSync('x25519', {});

  // Check that keys were generated
  if (!alice.privateKey || !(alice.privateKey instanceof ArrayBuffer)) {
    throw new Error('Failed to generate private key for Alice');
  }
  if (!bob.publicKey || !(bob.publicKey instanceof ArrayBuffer)) {
    throw new Error('Failed to generate public key for Bob');
  }

  // Create KeyObject instances from the raw keys using the factory method
  const privateKey = KeyObject.createKeyObject('private', alice.privateKey);
  const publicKey = KeyObject.createKeyObject('public', bob.publicKey);

  // Use the keys for Diffie-Hellman
  const sharedSecret = crypto.diffieHellman({
    privateKey,
    publicKey,
  });
  void expect(Buffer.isBuffer(sharedSecret)).to.be.true;
});

test(SUITE, 'x25519 - shared secret symmetry', () => {
  // Generate key pairs
  const alice = crypto.generateKeyPairSync('x25519', {});
  const bob = crypto.generateKeyPairSync('x25519', {});

  // Create KeyObject instances
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

  // Compute shared secrets from both sides
  const sharedSecretAlice = crypto.diffieHellman({
    privateKey: alicePrivate,
    publicKey: bobPublic,
  }) as Buffer;

  const sharedSecretBob = crypto.diffieHellman({
    privateKey: bobPrivate,
    publicKey: alicePublic,
  }) as Buffer;

  // Verify both sides compute the same shared secret
  void expect(Buffer.isBuffer(sharedSecretAlice)).to.be.true;
  void expect(Buffer.isBuffer(sharedSecretBob)).to.be.true;
  void expect(sharedSecretAlice.equals(sharedSecretBob)).to.be.true;
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

  // X25519 shared secrets should be exactly 32 bytes
  void expect(sharedSecret.length).to.equal(32);

  // Should not be all zeros (extremely unlikely with proper implementation)
  const allZeros = Buffer.alloc(32, 0);
  void expect(sharedSecret.equals(allZeros)).to.be.false;

  // Should be deterministic - same keys produce same secret
  const sharedSecret2 = crypto.diffieHellman({
    privateKey: alicePrivate,
    publicKey: bobPublic,
  }) as Buffer;
  void expect(sharedSecret.equals(sharedSecret2)).to.be.true;
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

  // Different public keys should produce different shared secrets
  void expect(secretAliceBob.equals(secretAliceCharlie)).to.be.false;
});

test(SUITE, 'x25519 - error handling', () => {
  const alice = crypto.generateKeyPairSync('x25519', {});

  const alicePrivate = KeyObject.createKeyObject(
    'private',
    alice.privateKey as ArrayBuffer,
  );

  // Should throw when creating KeyObject with invalid key data
  void expect(() => {
    KeyObject.createKeyObject('public', new ArrayBuffer(16)); // Invalid size
  }).to.throw();

  // Should throw when using invalid key types
  void expect(() => {
    crypto.diffieHellman({
      privateKey: alicePrivate,
      publicKey: {} as KeyObject,
    });
  }).to.throw();
});
