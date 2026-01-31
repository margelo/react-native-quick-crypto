import { test } from '../util';
import { Buffer } from '@craftzdog/react-native-buffer';
import crypto from 'react-native-quick-crypto';
import { assert } from 'chai';

const SUITE = 'ecdh';

test(SUITE, 'should create ECDH instance with P-256', () => {
  const ecdh = crypto.createECDH('prime256v1');
  assert.isOk(ecdh);
});

test(SUITE, 'should generate keys for P-256', () => {
  const ecdh = crypto.createECDH('prime256v1');
  const keys = ecdh.generateKeys();
  assert.isOk(keys);
  assert.isTrue(Buffer.isBuffer(keys), 'keys should be a Buffer');
  assert.isOk(ecdh.getPublicKey());
  assert.isOk(ecdh.getPrivateKey());
});

test(SUITE, 'should switch between curves', () => {
  const ecdh1 = crypto.createECDH('prime256v1');
  ecdh1.generateKeys();

  const ecdh2 = crypto.createECDH('secp384r1');
  ecdh2.generateKeys();

  assert.notEqual(
    ecdh1.getPrivateKey().toString('hex'),
    ecdh2.getPrivateKey().toString('hex'),
  );
});

test(SUITE, 'should compute shared secret', () => {
  const alice = crypto.createECDH('prime256v1');
  alice.generateKeys();

  const bob = crypto.createECDH('prime256v1');
  bob.generateKeys();

  const aliceSecret = alice.computeSecret(bob.getPublicKey());
  const bobSecret = bob.computeSecret(alice.getPublicKey());

  assert.strictEqual(aliceSecret.toString('hex'), bobSecret.toString('hex'));
});

test(SUITE, 'should set private key', () => {
  const alice = crypto.createECDH('prime256v1');
  alice.generateKeys();
  const priv = alice.getPrivateKey();

  const alice2 = crypto.createECDH('prime256v1');
  alice2.setPrivateKey(priv);

  const pub1 = alice.getPublicKey();
  const pub2 = alice2.getPublicKey();

  assert.strictEqual(pub1.toString('hex'), pub2.toString('hex'));
});

test(SUITE, 'should work with string input', () => {
  const alice = crypto.createECDH('prime256v1');
  alice.generateKeys();
  const bob = crypto.createECDH('prime256v1');
  bob.generateKeys();

  const bobPubHex = bob.getPublicKey().toString('hex');
  const secret = alice.computeSecret(bobPubHex, 'hex');
  assert.isOk(secret);
});
