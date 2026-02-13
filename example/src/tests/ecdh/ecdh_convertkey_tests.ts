import { test } from '../util';
import { createECDH, ECDH, Buffer } from 'react-native-quick-crypto';
import { assert } from 'chai';

const SUITE = 'ecdh';

test(SUITE, 'convertKey: uncompressed to compressed', () => {
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  const uncompressed = ecdh.getPublicKey() as Buffer;

  // Uncompressed keys start with 0x04
  assert.strictEqual(uncompressed[0], 0x04);

  const compressed = ECDH.convertKey(
    uncompressed,
    'prime256v1',
    undefined,
    undefined,
    'compressed',
  ) as Buffer;

  // Compressed keys start with 0x02 or 0x03
  assert.isTrue(
    compressed[0] === 0x02 || compressed[0] === 0x03,
    'compressed key should start with 0x02 or 0x03',
  );
  // Compressed is shorter than uncompressed
  assert.isTrue(compressed.length < uncompressed.length);
});

test(SUITE, 'convertKey: compressed to uncompressed', () => {
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  const uncompressed = ecdh.getPublicKey() as Buffer;

  const compressed = ECDH.convertKey(
    uncompressed,
    'prime256v1',
    undefined,
    undefined,
    'compressed',
  ) as Buffer;

  const back = ECDH.convertKey(
    compressed,
    'prime256v1',
    undefined,
    undefined,
    'uncompressed',
  ) as Buffer;

  assert.strictEqual(
    back.toString('hex'),
    uncompressed.toString('hex'),
    'roundtrip should produce the same key',
  );
});

test(SUITE, 'convertKey: hybrid format', () => {
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  const uncompressed = ecdh.getPublicKey() as Buffer;

  const hybrid = ECDH.convertKey(
    uncompressed,
    'prime256v1',
    undefined,
    undefined,
    'hybrid',
  ) as Buffer;

  // Hybrid keys start with 0x06 or 0x07
  assert.isTrue(
    hybrid[0] === 0x06 || hybrid[0] === 0x07,
    'hybrid key should start with 0x06 or 0x07',
  );
});

test(SUITE, 'convertKey: with hex encoding', () => {
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  const pubHex = ecdh.getPublicKey('hex') as string;

  const compressed = ECDH.convertKey(
    pubHex,
    'prime256v1',
    'hex',
    'hex',
    'compressed',
  ) as string;

  assert.isString(compressed);
  assert.isTrue(
    compressed.startsWith('02') || compressed.startsWith('03'),
    'compressed hex key should start with 02 or 03',
  );
});
