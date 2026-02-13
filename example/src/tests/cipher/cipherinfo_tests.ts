import { test } from '../util';
import { getCipherInfo } from 'react-native-quick-crypto';
import { assert } from 'chai';

const SUITE = 'cipher';

test(SUITE, 'getCipherInfo: returns info for aes-256-cbc', () => {
  const info = getCipherInfo('aes-256-cbc');
  assert.isOk(info);
  assert.strictEqual(info!.name, 'aes-256-cbc');
  assert.strictEqual(info!.keyLength, 32);
  assert.strictEqual(info!.ivLength, 16);
  assert.strictEqual(info!.blockSize, 16);
  assert.strictEqual(info!.mode, 'cbc');
  assert.isNumber(info!.nid);
});

test(SUITE, 'getCipherInfo: returns info for aes-128-gcm', () => {
  const info = getCipherInfo('aes-128-gcm');
  assert.isOk(info);
  assert.strictEqual(info!.name, 'id-aes128-gcm');
  assert.strictEqual(info!.keyLength, 16);
  assert.strictEqual(info!.ivLength, 12);
  assert.strictEqual(info!.mode, 'gcm');
});

test(SUITE, 'getCipherInfo: returns info for chacha20-poly1305', () => {
  const info = getCipherInfo('chacha20-poly1305');
  assert.isOk(info);
  assert.strictEqual(info!.keyLength, 32);
  assert.strictEqual(info!.ivLength, 12);
});

test(SUITE, 'getCipherInfo: returns undefined for unknown cipher', () => {
  const info = getCipherInfo('not-a-real-cipher');
  assert.isUndefined(info);
});

test(SUITE, 'getCipherInfo: accepts custom keyLength', () => {
  const info = getCipherInfo('aes-128-cbc', { keyLength: 16 });
  assert.isOk(info);
  assert.strictEqual(info!.keyLength, 16);
});

test(SUITE, 'getCipherInfo: rejects invalid keyLength', () => {
  const info = getCipherInfo('aes-128-cbc', { keyLength: 7 });
  assert.isUndefined(info);
});

test(SUITE, 'getCipherInfo: stream cipher has no blockSize', () => {
  const info = getCipherInfo('chacha20');
  if (info) {
    assert.isUndefined(info.blockSize);
  }
});
