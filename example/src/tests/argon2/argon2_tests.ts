import { test } from '../util';
import { argon2Sync, argon2, Buffer } from 'react-native-quick-crypto';
import { assert } from 'chai';

const SUITE = 'argon2';

// RFC 9106 §5 official test vectors (32-byte tags). The (P, S, K, X, t, m,
// p, T, v) tuple is identical across the three modes; only the variant and
// resulting tag differ.
//
// https://www.rfc-editor.org/rfc/rfc9106#section-5
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

const RFC_9106_TAGS = {
  argon2d: '512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb',
  argon2i: 'c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8',
  argon2id: '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
} as const;

test(SUITE, 'argon2Sync: argon2id matches RFC 9106 §5 KAT', () => {
  // Pass `version: 0x13` explicitly (matches RFC_PARAMS) so a future change
  // to the native binding's default version cannot silently break the KAT.
  const result = argon2Sync('argon2id', { ...RFC_PARAMS, version: 0x13 });
  assert.strictEqual(result.length, 32);
  assert.strictEqual(
    Buffer.from(result).toString('hex'),
    RFC_9106_TAGS.argon2id,
  );
});

test(SUITE, 'argon2Sync: argon2i matches RFC 9106 §5 KAT', () => {
  const result = argon2Sync('argon2i', { ...RFC_PARAMS, version: 0x13 });
  assert.strictEqual(result.length, 32);
  assert.strictEqual(
    Buffer.from(result).toString('hex'),
    RFC_9106_TAGS.argon2i,
  );
});

test(SUITE, 'argon2Sync: argon2d matches RFC 9106 §5 KAT', () => {
  const result = argon2Sync('argon2d', { ...RFC_PARAMS, version: 0x13 });
  assert.strictEqual(result.length, 32);
  assert.strictEqual(
    Buffer.from(result).toString('hex'),
    RFC_9106_TAGS.argon2d,
  );
});

test(SUITE, 'argon2: async argon2id matches RFC 9106 §5 KAT', () => {
  return new Promise<void>((resolve, reject) => {
    argon2('argon2id', { ...RFC_PARAMS, version: 0x13 }, (err, result) => {
      try {
        assert.isNull(err);
        assert.strictEqual(
          Buffer.from(result).toString('hex'),
          RFC_9106_TAGS.argon2id,
        );
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
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

// --- Numeric parameter validation (Phase 1.1: validateUInt + Phase 3.2 RFC 9106) ---
//
// `static_cast<uint32_t>(NaN | +/-Infinity | -1)` is undefined behavior in
// C++. The C++ layer's validateUInt helper used to be the first line of
// defense; Phase 3.2 added a TS-side RFC 9106 §3.1 check that fires
// earlier and produces a clearer message. The regex below matches the
// new RFC 9106 wording.

const baseParams = {
  message: Buffer.from('password'),
  nonce: Buffer.from('somesalt0000'),
  parallelism: 1,
  tagLength: 32,
  memory: 64,
  passes: 3,
};

test(SUITE, 'argon2Sync: rejects NaN parallelism', () => {
  assert.throws(() => {
    argon2Sync('argon2id', { ...baseParams, parallelism: NaN });
  }, /parallelism.*NaN/i);
});

test(SUITE, 'argon2Sync: rejects +Infinity memory', () => {
  assert.throws(() => {
    argon2Sync('argon2id', { ...baseParams, memory: Infinity });
  }, /memory.*infinity/i);
});

test(SUITE, 'argon2Sync: rejects -Infinity passes', () => {
  assert.throws(() => {
    argon2Sync('argon2id', { ...baseParams, passes: -Infinity });
  }, /passes.*infinity/i);
});

test(SUITE, 'argon2Sync: rejects negative tagLength', () => {
  assert.throws(() => {
    argon2Sync('argon2id', { ...baseParams, tagLength: -1 });
  }, /Invalid Argon2 tagLength: -1/);
});

test(SUITE, 'argon2Sync: rejects fractional passes', () => {
  assert.throws(() => {
    argon2Sync('argon2id', { ...baseParams, passes: 3.5 });
  }, /Invalid Argon2 passes: 3\.5/);
});

test(SUITE, 'argon2Sync: rejects out-of-range memory', () => {
  // memory is uint32_t — anything beyond UINT32_MAX must be rejected.
  assert.throws(() => {
    argon2Sync('argon2id', { ...baseParams, memory: 2 ** 32 });
  }, /Invalid Argon2 memory: 4294967296/);
});

test(SUITE, 'argon2: async path also rejects NaN parallelism', () => {
  return new Promise<void>((resolve, reject) => {
    argon2('argon2id', { ...baseParams, parallelism: NaN }, err => {
      try {
        assert.isNotNull(err);
        assert.match(err!.message, /parallelism.*NaN/i);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
});

// --- RFC 9106 §3.1 minimum-bound validation (Phase 3.2) ---

test(SUITE, 'argon2Sync: rejects parallelism = 0 (RFC 9106 mins)', () => {
  assert.throws(() => {
    argon2Sync('argon2id', { ...baseParams, parallelism: 0 });
  }, /parallelism: 0/);
});

test(SUITE, 'argon2Sync: rejects tagLength < 4 (RFC 9106 mins)', () => {
  assert.throws(() => {
    argon2Sync('argon2id', { ...baseParams, tagLength: 3 });
  }, /tagLength: 3/);
});

test(SUITE, 'argon2Sync: rejects passes = 0 (RFC 9106 mins)', () => {
  assert.throws(() => {
    argon2Sync('argon2id', { ...baseParams, passes: 0 });
  }, /passes: 0/);
});

test(SUITE, 'argon2Sync: rejects memory < 8 * parallelism (RFC 9106)', () => {
  // p=4 ⇒ memory must be ≥ 32 KiB; 16 KiB must be rejected.
  assert.throws(() => {
    argon2Sync('argon2id', {
      ...baseParams,
      parallelism: 4,
      memory: 16,
    });
  }, /memory: 16/);
});

test(SUITE, 'argon2Sync: rejects nonce shorter than 8 bytes (RFC 9106)', () => {
  assert.throws(() => {
    argon2Sync('argon2id', {
      ...baseParams,
      nonce: Buffer.from('1234567'), // 7 bytes
    });
  }, /nonce length: 7/);
});

test(SUITE, 'argon2Sync: rejects unsupported version', () => {
  assert.throws(() => {
    argon2Sync('argon2id', { ...baseParams, version: 0x42 });
  }, /Invalid Argon2 version/);
});
