import { test } from '../util';
import crypto, { Buffer } from 'react-native-quick-crypto';
import { assert } from 'chai';

const SUITE = 'dh';

// RFC 3526 MODP Group 14 prime (2048-bit) for testing with explicit prime
const MODP14_PRIME =
  'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
  '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
  'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
  'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
  'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
  'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
  '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
  '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
  'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
  'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
  '15728E5A8AACAA68FFFFFFFFFFFFFFFF';

test(
  SUITE,
  'should create DiffieHellman with prime and numeric generator',
  () => {
    const prime = Buffer.from(MODP14_PRIME, 'hex');
    const dh = crypto.createDiffieHellman(prime, 2);

    assert.strictEqual(dh.getPrime('hex'), prime.toString('hex').toLowerCase());
    assert.strictEqual(dh.getGenerator('hex'), '02');
  },
);

test(
  SUITE,
  'should create DiffieHellman with prime and Buffer generator',
  () => {
    const prime = Buffer.from(MODP14_PRIME, 'hex');
    const generator = Buffer.from([2]);
    const dh = crypto.createDiffieHellman(prime, generator);

    assert.strictEqual(dh.getPrime('hex'), prime.toString('hex').toLowerCase());
    assert.strictEqual(
      dh.getGenerator('hex'),
      generator.toString('hex').toLowerCase(),
    );
  },
);

test(SUITE, 'should compute shared secret', () => {
  const alice = crypto.getDiffieHellman('modp14');
  alice.generateKeys();

  const bob = crypto.getDiffieHellman('modp14');
  bob.generateKeys();

  const aliceSecret = alice.computeSecret(bob.getPublicKey());
  const bobSecret = bob.computeSecret(alice.getPublicKey());

  assert.strictEqual(aliceSecret.toString('hex'), bobSecret.toString('hex'));
});

test(SUITE, 'should set keys', () => {
  const alice = crypto.getDiffieHellman('modp14');
  alice.generateKeys();

  const bob = crypto.createDiffieHellman(
    alice.getPrime(),
    alice.getGenerator(),
  );
  bob.setPublicKey(alice.getPublicKey());
  bob.setPrivateKey(alice.getPrivateKey());

  assert.strictEqual(bob.getPublicKey('hex'), alice.getPublicKey('hex'));
  assert.strictEqual(bob.getPrivateKey('hex'), alice.getPrivateKey('hex'));
});

test(SUITE, 'should create DiffieHellman from standard group', () => {
  const dh = crypto.getDiffieHellman('modp14');
  assert.isOk(dh);
  const prime = dh.getPrime();
  assert.isTrue(Buffer.isBuffer(prime));
  assert.strictEqual(prime.length, 256);
  assert.strictEqual(dh.getGenerator('hex'), '02');
});

test(SUITE, 'should reject prime length below 2048 bits', () => {
  assert.throws(() => {
    crypto.createDiffieHellman(512);
  }, /prime length must be at least 2048 bits/);
});

// createDiffieHellmanGroup alias
test(
  SUITE,
  'createDiffieHellmanGroup should be an alias for getDiffieHellman',
  () => {
    const dh1 = crypto.getDiffieHellman('modp14');
    const dh2 = crypto.createDiffieHellmanGroup('modp14');

    assert.strictEqual(dh1.getPrime('hex'), dh2.getPrime('hex'));
    assert.strictEqual(dh1.getGenerator('hex'), dh2.getGenerator('hex'));
  },
);

test(SUITE, 'createDiffieHellmanGroup should throw for unknown group', () => {
  assert.throws(() => {
    crypto.createDiffieHellmanGroup('modp999');
  }, /Unknown group/);
});

// verifyError property
test(SUITE, 'verifyError should return 0 for valid DH params', () => {
  const dh = crypto.getDiffieHellman('modp14');
  assert.strictEqual(dh.verifyError, 0);
});

test(SUITE, 'verifyError should return 0 for created DH', () => {
  const prime = Buffer.from(MODP14_PRIME, 'hex');
  const dh = crypto.createDiffieHellman(prime, 2);
  assert.strictEqual(dh.verifyError, 0);
});
