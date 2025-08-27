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
