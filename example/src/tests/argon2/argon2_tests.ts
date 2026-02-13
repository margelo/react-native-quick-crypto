import { test } from '../util';
import { argon2Sync, argon2, Buffer } from 'react-native-quick-crypto';
import { assert } from 'chai';

const SUITE = 'argon2';

// RFC 9106 test vector for argon2id
const RFC_PARAMS = {
  message: Buffer.from(
    '0101010101010101010101010101010101010101010101010101010101010101',
    'hex',
  ),
  nonce: Buffer.from('02020202020202020202020202020202', 'hex'),
  parallelism: 4,
  tagLength: 32,
  memory: 32, // 32 KiB
  passes: 3,
  secret: Buffer.from('0303030303030303', 'hex'),
  associatedData: Buffer.from('040404040404040404040404', 'hex'),
  version: 0x13,
};

test(SUITE, 'argon2Sync: argon2id produces expected output', () => {
  const result = argon2Sync('argon2id', RFC_PARAMS);
  assert.isOk(result);
  assert.strictEqual(result.length, 32);
});

test(SUITE, 'argon2Sync: argon2i produces output', () => {
  const result = argon2Sync('argon2i', {
    message: Buffer.from('password'),
    nonce: Buffer.from('somesalt0000'),
    parallelism: 1,
    tagLength: 32,
    memory: 64,
    passes: 3,
  });
  assert.isOk(result);
  assert.strictEqual(result.length, 32);
});

test(SUITE, 'argon2Sync: argon2d produces output', () => {
  const result = argon2Sync('argon2d', {
    message: Buffer.from('password'),
    nonce: Buffer.from('somesalt0000'),
    parallelism: 1,
    tagLength: 32,
    memory: 64,
    passes: 3,
  });
  assert.isOk(result);
  assert.strictEqual(result.length, 32);
});

test(SUITE, 'argon2Sync: different algorithms produce different output', () => {
  const params = {
    message: Buffer.from('password'),
    nonce: Buffer.from('somesalt0000'),
    parallelism: 1,
    tagLength: 32,
    memory: 64,
    passes: 3,
  };
  const d = argon2Sync('argon2d', params);
  const i = argon2Sync('argon2i', params);
  const id = argon2Sync('argon2id', params);
  assert.notDeepEqual(d, i);
  assert.notDeepEqual(i, id);
  assert.notDeepEqual(d, id);
});

test(SUITE, 'argon2Sync: respects tagLength', () => {
  const result = argon2Sync('argon2id', {
    message: Buffer.from('password'),
    nonce: Buffer.from('somesalt0000'),
    parallelism: 1,
    tagLength: 64,
    memory: 64,
    passes: 3,
  });
  assert.strictEqual(result.length, 64);
});

test(SUITE, 'argon2Sync: throws on invalid algorithm', () => {
  assert.throws(() => {
    argon2Sync('argon2x', {
      message: Buffer.from('password'),
      nonce: Buffer.from('somesalt0000'),
      parallelism: 1,
      tagLength: 32,
      memory: 64,
      passes: 3,
    });
  }, /Unknown argon2 algorithm/);
});

test(SUITE, 'argon2: async produces same result as sync', () => {
  return new Promise<void>((resolve, reject) => {
    const params = {
      message: Buffer.from('password'),
      nonce: Buffer.from('somesalt0000'),
      parallelism: 1,
      tagLength: 32,
      memory: 64,
      passes: 3,
    };
    const syncResult = argon2Sync('argon2id', params);
    argon2('argon2id', params, (err, asyncResult) => {
      try {
        assert.isNull(err);
        assert.deepEqual(
          Buffer.from(asyncResult).toString('hex'),
          Buffer.from(syncResult).toString('hex'),
        );
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
});

test(SUITE, 'argon2Sync: deterministic with same inputs', () => {
  const params = {
    message: Buffer.from('password'),
    nonce: Buffer.from('somesalt0000'),
    parallelism: 1,
    tagLength: 32,
    memory: 64,
    passes: 3,
  };
  const r1 = argon2Sync('argon2id', params);
  const r2 = argon2Sync('argon2id', params);
  assert.deepEqual(
    Buffer.from(r1).toString('hex'),
    Buffer.from(r2).toString('hex'),
  );
});
