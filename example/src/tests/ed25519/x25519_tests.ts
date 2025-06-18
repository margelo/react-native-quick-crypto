import { expect } from 'chai';
import crypto, { KeyObject } from 'react-native-quick-crypto';
import { test } from '../util';

const SUITE = 'x25519';

test(SUITE, 'diffieHellman', () => {
  // Alice
  const A = crypto.generateKeyPairSync('x25519', {});
  if (!A.privateKey || !(A.privateKey instanceof ArrayBuffer))
    throw new Error('Failed to generate private key for Alice');
  const privateKey = new KeyObject('private', A.privateKey);

  // Bob
  const B = crypto.generateKeyPairSync('x25519', {});
  if (!B.publicKey || !(B.publicKey instanceof ArrayBuffer))
    throw new Error('Failed to generate public key for Bob');
  const publicKey = new KeyObject('public', B.publicKey);

  // Shared secret
  const sharedSecret = crypto.diffieHellman({
    privateKey,
    publicKey,
  });
  expect(sharedSecret).to.be.a('Buffer');
});
