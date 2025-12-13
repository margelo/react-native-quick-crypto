import { test } from '../util';
import { Buffer } from '@craftzdog/react-native-buffer';
import crypto from 'react-native-quick-crypto';
import { assert } from 'chai';

const SUITE = 'dh';

test(SUITE, 'should create DiffieHellman with size', () => {
  const dh = crypto.createDiffieHellman(512);
  const prime = dh.getPrime();
  assert.isOk(prime);
  // Size check approx
  assert.isAtLeast(prime.length, 64);
});

test(SUITE, 'should create DiffieHellman with prime', () => {
  // 512-bit prime (Group 1 from RFC 2409)
  const prime = Buffer.from(
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
      '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
      'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
      'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
      'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381' +
      'FFFFFFFFFFFFFFFF',
    'hex',
  );
  const generator = Buffer.from([2]);
  const dh = crypto.createDiffieHellman(prime, generator);

  assert.strictEqual(dh.getPrime('hex'), prime.toString('hex').toLowerCase());
  assert.strictEqual(
    dh.getGenerator('hex'),
    generator.toString('hex').toLowerCase(),
  );
});

test(SUITE, 'should compute shared secret', () => {
  const alice = crypto.createDiffieHellman(512);
  const aliceKeys = alice.generateKeys();

  const bob = crypto.createDiffieHellman(
    alice.getPrime(),
    alice.getGenerator(),
  );
  const bobKeys = bob.generateKeys();

  const aliceSecret = alice.computeSecret(bobKeys);
  const bobSecret = bob.computeSecret(aliceKeys);

  assert.strictEqual(aliceSecret.toString('hex'), bobSecret.toString('hex'));
});

test(SUITE, 'should set keys', () => {
  const alice = crypto.createDiffieHellman(512);
  alice.generateKeys();

  const dh2 = crypto.createDiffieHellman(
    alice.getPrime(),
    alice.getGenerator(),
  );
  dh2.setPublicKey(alice.getPublicKey());
  dh2.setPrivateKey(alice.getPrivateKey());

  assert.strictEqual(dh2.getPublicKey('hex'), alice.getPublicKey('hex'));
  assert.strictEqual(dh2.getPrivateKey('hex'), alice.getPrivateKey('hex'));
});

test(SUITE, 'should create DiffieHellman from standard group', () => {
  const dh = crypto.getDiffieHellman('modp14');
  assert.isOk(dh);
  const prime = dh.getPrime();
  assert.isTrue(Buffer.isBuffer(prime));
  // modp14 is 2048-bit group
  assert.strictEqual(prime.length, 256);
  assert.strictEqual(dh.getGenerator('hex'), '02');
});
