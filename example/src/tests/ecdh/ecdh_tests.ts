import { test } from '../util';
import crypto, { Buffer, getCurves } from 'react-native-quick-crypto';
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

test(SUITE, 'should set private key and compute secret for P-384', () => {
  const alice = crypto.createECDH('secp384r1');
  alice.generateKeys();
  const priv = alice.getPrivateKey();

  const alice2 = crypto.createECDH('secp384r1');
  alice2.setPrivateKey(priv);

  assert.strictEqual(
    alice.getPublicKey().toString('hex'),
    alice2.getPublicKey().toString('hex'),
  );

  const bob = crypto.createECDH('secp384r1');
  bob.generateKeys();

  const secret1 = alice.computeSecret(bob.getPublicKey());
  const secret2 = alice2.computeSecret(bob.getPublicKey());
  assert.strictEqual(secret1.toString('hex'), secret2.toString('hex'));
});

test(SUITE, 'should set private key and compute secret for P-521', () => {
  const alice = crypto.createECDH('secp521r1');
  alice.generateKeys();
  const priv = alice.getPrivateKey();

  const alice2 = crypto.createECDH('secp521r1');
  alice2.setPrivateKey(priv);

  assert.strictEqual(
    alice.getPublicKey().toString('hex'),
    alice2.getPublicKey().toString('hex'),
  );

  const bob = crypto.createECDH('secp521r1');
  bob.generateKeys();

  const secret1 = alice.computeSecret(bob.getPublicKey());
  const secret2 = alice2.computeSecret(bob.getPublicKey());
  assert.strictEqual(secret1.toString('hex'), secret2.toString('hex'));
});

test(SUITE, 'should set private key and compute secret for secp256k1', () => {
  const alice = crypto.createECDH('secp256k1');
  alice.generateKeys();
  const priv = alice.getPrivateKey();

  const alice2 = crypto.createECDH('secp256k1');
  alice2.setPrivateKey(priv);

  assert.strictEqual(
    alice.getPublicKey().toString('hex'),
    alice2.getPublicKey().toString('hex'),
  );

  const bob = crypto.createECDH('secp256k1');
  bob.generateKeys();

  const secret1 = alice.computeSecret(bob.getPublicKey());
  const secret2 = alice2.computeSecret(bob.getPublicKey());
  assert.strictEqual(secret1.toString('hex'), secret2.toString('hex'));
});

test(SUITE, 'should compute secret with sliced public key buffer', () => {
  const alice = crypto.createECDH('secp256k1');
  alice.generateKeys();

  const bob = crypto.createECDH('secp256k1');
  bob.generateKeys();

  const bobPub = bob.getPublicKey() as Buffer;
  assert.isTrue(Buffer.isBuffer(bobPub), 'public key should be a Buffer');

  // Force non-zero byteOffset by slicing from a larger packet.
  const packet = Buffer.concat([
    Buffer.from([0xaa, 0xbb]),
    bobPub,
    Buffer.from([0xcc]),
  ]);
  const bobPubSlice = packet.slice(2, 2 + bobPub.length);
  assert.strictEqual(
    bobPubSlice.length,
    bobPub.length,
    'slice length should match key length',
  );
  assert.isAbove(
    bobPubSlice.byteOffset,
    0,
    'slice should have non-zero byteOffset',
  );

  const secretFromOriginal = alice.computeSecret(bobPub);
  const secretFromSlice = alice.computeSecret(bobPubSlice);

  assert.strictEqual(
    secretFromSlice.toString('hex'),
    secretFromOriginal.toString('hex'),
    'sliced public key should derive the same shared secret',
  );
});

// --- Peer public-key validation (security audit Phase 0.3) ---
//
// Without an explicit point-on-curve check, an attacker can mount an
// invalid-curve attack: send a point on a related, weaker curve and recover
// bits of the victim's private key from the resulting "shared secret".

test(SUITE, 'computeSecret should reject empty peer key (malformed)', () => {
  const alice = crypto.createECDH('prime256v1');
  alice.generateKeys();
  assert.throws(() => {
    alice.computeSecret(Buffer.alloc(0));
  }, /malformed|peer/i);
});

test(SUITE, 'computeSecret should reject the identity point', () => {
  const alice = crypto.createECDH('prime256v1');
  alice.generateKeys();
  // SEC1 encodes the point at infinity as a single 0x00 octet.
  assert.throws(() => {
    alice.computeSecret(Buffer.from([0x00]));
  }, /identity|malformed|peer/i);
});

test(SUITE, 'computeSecret should reject peer key with wrong length', () => {
  const alice = crypto.createECDH('prime256v1');
  alice.generateKeys();
  // 64 random bytes — not a valid uncompressed P-256 point (would need 65).
  assert.throws(() => {
    alice.computeSecret(Buffer.alloc(64, 0xab));
  }, /malformed|peer/i);
});

test(
  SUITE,
  'computeSecret should reject peer key from a different curve',
  () => {
    // Send a P-384 (97-byte) public key to a P-256 (65-byte) instance — the
    // length and/or coordinates won't match the configured curve.
    const alice = crypto.createECDH('prime256v1');
    alice.generateKeys();
    const evil = crypto.createECDH('secp384r1');
    evil.generateKeys();
    assert.throws(() => {
      alice.computeSecret(evil.getPublicKey());
    }, /malformed|not on the configured curve|peer/i);
  },
);

test(
  SUITE,
  'computeSecret should reject point not on the configured curve',
  () => {
    // Take a valid P-256 pubkey and flip a bit in the y-coordinate.
    // The decoded (x, y) won't satisfy y^2 = x^3 + ax + b on P-256, so
    // EC_POINT_is_on_curve must reject it.
    const alice = crypto.createECDH('prime256v1');
    alice.generateKeys();
    const bob = crypto.createECDH('prime256v1');
    bob.generateKeys();
    const pub = Buffer.from(bob.getPublicKey() as Buffer);
    // Flip a bit in the last byte (y-coordinate LSB) — overwhelmingly unlikely
    // to land on the curve again.
    pub[pub.length - 1] = pub[pub.length - 1]! ^ 0x01;
    assert.throws(() => {
      alice.computeSecret(pub);
    }, /not on the configured curve|malformed|peer/i);
  },
);

test(SUITE, 'getCurves - should return array of supported curves', () => {
  const curves = getCurves();
  assert.isArray(curves);
  assert.isAbove(curves.length, 0, 'should have at least one curve');

  const expectedCurves = ['prime256v1', 'secp384r1', 'secp521r1', 'secp256k1'];
  for (const curve of expectedCurves) {
    assert.include(curves, curve, `should include ${curve}`);
  }

  const isSorted = curves.every(
    (val: string, i: number) => i === 0 || val >= curves[i - 1]!,
  );
  assert.isTrue(isSorted, 'curves should be sorted alphabetically');
});

test(SUITE, 'getCurves - should match crypto.getCurves()', () => {
  const named = getCurves();
  const fromDefault = crypto.getCurves();
  assert.deepEqual(named, fromDefault);
});
