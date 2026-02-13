import { test } from '../util';
import {
  subtle,
  KeyObject,
  CryptoKey,
  isCryptoKeyPair,
  Buffer,
} from 'react-native-quick-crypto';
import { assert } from 'chai';

const SUITE = 'keys';

test(SUITE, 'KeyObject.from() extracts KeyObject from CryptoKey', async () => {
  const result = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  assert.isTrue(isCryptoKeyPair(result));
  if (!isCryptoKeyPair(result)) return;

  const keyObject = KeyObject.from(result.publicKey as CryptoKey);
  assert.isOk(keyObject);
  assert.strictEqual(keyObject.type, 'public');
});

test(SUITE, 'KeyObject.from() throws for non-CryptoKey', () => {
  assert.throws(() => {
    // @ts-expect-error testing invalid input
    KeyObject.from('not-a-key');
  }, TypeError);
});

test(
  SUITE,
  'KeyObject.toCryptoKey() wraps KeyObject as CryptoKey',
  async () => {
    const result = await subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    assert.isTrue(isCryptoKeyPair(result));
    if (!isCryptoKeyPair(result)) return;

    const keyObject = KeyObject.from(result.publicKey as CryptoKey);
    const cryptoKey = keyObject.toCryptoKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify'],
    );

    assert.isOk(cryptoKey);
    assert.strictEqual(cryptoKey.type, 'public');
    assert.strictEqual(cryptoKey.extractable, true);
    assert.deepEqual(cryptoKey.usages, ['verify']);
    assert.strictEqual(cryptoKey.algorithm.name, 'ECDSA');
  },
);

test(
  SUITE,
  'KeyObject.from() and toCryptoKey() roundtrip preserves key',
  async () => {
    const keyPair = await subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    assert.isTrue(isCryptoKeyPair(keyPair));
    if (!isCryptoKeyPair(keyPair)) return;

    const keyObject = KeyObject.from(keyPair.publicKey as CryptoKey);
    const cryptoKey = keyObject.toCryptoKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify'],
    );

    // Verify the roundtripped key can still be used
    const exported1 = await subtle.exportKey(
      'raw',
      keyPair.publicKey as CryptoKey,
    );
    const exported2 = await subtle.exportKey('raw', cryptoKey);
    assert.strictEqual(
      Buffer.from(exported1 as ArrayBuffer).toString('hex'),
      Buffer.from(exported2 as ArrayBuffer).toString('hex'),
    );
  },
);
