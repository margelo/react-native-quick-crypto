import { expect } from 'chai';
import {
  Blake3,
  Buffer,
  createBlake3,
  blake3,
} from 'react-native-quick-crypto';
import { test } from '../util';

const SUITE = 'blake3';

// Official BLAKE3 test vectors from https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
const TEST_VECTORS = {
  // Input: empty
  empty: {
    input: '',
    hash: 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262',
  },
  // Input: 1 byte (0x00)
  oneByte: {
    input: Buffer.from([0]),
    hash: '2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213',
  },
  // Input: "abc"
  abc: {
    input: 'abc',
    hash: '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85',
  },
};

// Basic hash tests
test(SUITE, 'blake3 - hash empty string', () => {
  const result = blake3('');
  expect(Buffer.from(result).toString('hex')).to.equal(TEST_VECTORS.empty.hash);
});

test(SUITE, 'blake3 - hash single byte', () => {
  const result = blake3(TEST_VECTORS.oneByte.input);
  expect(Buffer.from(result).toString('hex')).to.equal(
    TEST_VECTORS.oneByte.hash,
  );
});

test(SUITE, 'blake3 - hash "abc"', () => {
  const result = blake3('abc');
  expect(Buffer.from(result).toString('hex')).to.equal(TEST_VECTORS.abc.hash);
});

test(SUITE, 'blake3 - hash Buffer', () => {
  const result = blake3(Buffer.from('hello world'));
  expect(result).to.be.instanceOf(Uint8Array);
  expect(result.length).to.equal(32);
});

test(SUITE, 'blake3 - hash Uint8Array', () => {
  const data = new Uint8Array([1, 2, 3, 4, 5]);
  const result = blake3(data);
  expect(result).to.be.instanceOf(Uint8Array);
  expect(result.length).to.equal(32);
});

// Variable output length (XOF)
test(SUITE, 'blake3 - custom output length (dkLen)', () => {
  const result16 = blake3('test', { dkLen: 16 });
  const result64 = blake3('test', { dkLen: 64 });
  const result128 = blake3('test', { dkLen: 128 });

  expect(result16.length).to.equal(16);
  expect(result64.length).to.equal(64);
  expect(result128.length).to.equal(128);
});

test(SUITE, 'blake3 - XOF produces consistent prefix', () => {
  const result32 = blake3('test', { dkLen: 32 });
  const result64 = blake3('test', { dkLen: 64 });

  // First 32 bytes should be identical
  expect(Buffer.from(result64.slice(0, 32)).toString('hex')).to.equal(
    Buffer.from(result32).toString('hex'),
  );
});

// Keyed mode (MAC)
test(SUITE, 'blake3 - keyed mode (MAC)', () => {
  const key = new Uint8Array(32).fill(0x42);
  const result = blake3('hello', { key });

  expect(result).to.be.instanceOf(Uint8Array);
  expect(result.length).to.equal(32);
});

test(SUITE, 'blake3 - keyed mode produces different output', () => {
  const key1 = new Uint8Array(32).fill(0x01);
  const key2 = new Uint8Array(32).fill(0x02);

  const result1 = blake3('test', { key: key1 });
  const result2 = blake3('test', { key: key2 });
  const resultNoKey = blake3('test');

  expect(Buffer.from(result1).toString('hex')).to.not.equal(
    Buffer.from(result2).toString('hex'),
  );
  expect(Buffer.from(result1).toString('hex')).to.not.equal(
    Buffer.from(resultNoKey).toString('hex'),
  );
});

test(SUITE, 'blake3 - keyed mode rejects invalid key length', () => {
  const shortKey = new Uint8Array(16);
  expect(() => blake3('test', { key: shortKey })).to.throw(
    /key must be exactly 32 bytes/,
  );
});

// KDF mode
test(SUITE, 'blake3 - derive key mode', () => {
  const result = blake3('input key material', {
    context: 'example.com 2024-01-01 session key',
  });

  expect(result).to.be.instanceOf(Uint8Array);
  expect(result.length).to.equal(32);
});

test(SUITE, 'blake3 - derive key mode with custom length', () => {
  const result = blake3('input key material', {
    context: 'example.com 2024-01-01 encryption key',
    dkLen: 64,
  });

  expect(result.length).to.equal(64);
});

test(SUITE, 'blake3 - derive key mode different contexts', () => {
  const ctx1 = 'app1 2024 encryption';
  const ctx2 = 'app2 2024 encryption';

  const result1 = blake3('same input', { context: ctx1 });
  const result2 = blake3('same input', { context: ctx2 });

  expect(Buffer.from(result1).toString('hex')).to.not.equal(
    Buffer.from(result2).toString('hex'),
  );
});

test(SUITE, 'blake3 - cannot use both key and context', () => {
  const key = new Uint8Array(32);
  expect(() => blake3('test', { key, context: 'some context' })).to.throw(
    /cannot use both key and context/,
  );
});

// Streaming API with Blake3 class
test(SUITE, 'Blake3 class - basic streaming', () => {
  const hasher = new Blake3();
  hasher.update('hello ');
  hasher.update('world');
  const result = hasher.digest();

  const oneShot = blake3('hello world');
  expect(result.toString('hex')).to.equal(Buffer.from(oneShot).toString('hex'));
});

test(SUITE, 'Blake3 class - chained updates', () => {
  const hasher = new Blake3();
  const result = hasher.update('a').update('b').update('c').digest();

  const oneShot = blake3('abc');
  expect(result.toString('hex')).to.equal(Buffer.from(oneShot).toString('hex'));
});

test(SUITE, 'Blake3 class - digest with encoding', () => {
  const hasher = new Blake3();
  hasher.update('test');
  const hexResult = hasher.digest('hex');

  expect(typeof hexResult).to.equal('string');
  expect(hexResult.length).to.equal(64); // 32 bytes = 64 hex chars
});

test(SUITE, 'Blake3 class - digest with length', () => {
  const hasher = new Blake3();
  hasher.update('test');
  const result = hasher.digest(64);

  expect(result.length).to.equal(64);
});

test(SUITE, 'Blake3 class - digestLength method', () => {
  const hasher = new Blake3();
  hasher.update('test');
  const result = hasher.digestLength(128);

  expect(result.length).to.equal(128);
});

test(SUITE, 'Blake3 class - keyed mode', () => {
  const key = new Uint8Array(32).fill(0xaa);
  const hasher = new Blake3({ key });
  hasher.update('message');
  const result = hasher.digest();

  const oneShot = blake3('message', { key });
  expect(result.toString('hex')).to.equal(Buffer.from(oneShot).toString('hex'));
});

test(SUITE, 'Blake3 class - derive key mode', () => {
  const context = 'test context';
  const hasher = new Blake3({ context });
  hasher.update('input');
  const result = hasher.digest();

  const oneShot = blake3('input', { context });
  expect(result.toString('hex')).to.equal(Buffer.from(oneShot).toString('hex'));
});

// Copy functionality
test(SUITE, 'Blake3 class - copy creates independent instance', () => {
  const hasher1 = new Blake3();
  hasher1.update('hello');

  const hasher2 = hasher1.copy();
  hasher1.update(' world');
  hasher2.update(' there');

  const result1 = hasher1.digest('hex');
  const result2 = hasher2.digest('hex');

  expect(result1).to.not.equal(result2);
  expect(result1).to.equal(Buffer.from(blake3('hello world')).toString('hex'));
  expect(result2).to.equal(Buffer.from(blake3('hello there')).toString('hex'));
});

test(SUITE, 'Blake3 class - copy preserves mode', () => {
  const key = new Uint8Array(32).fill(0x55);
  const hasher1 = new Blake3({ key });
  hasher1.update('part1');

  const hasher2 = hasher1.copy();
  hasher2.update('part2');

  const result = hasher2.digest();
  expect(result.length).to.equal(32);
});

// Reset functionality
test(SUITE, 'Blake3 class - reset clears state', () => {
  const hasher = new Blake3();
  hasher.update('garbage');
  hasher.reset();
  hasher.update('test');

  const result = hasher.digest();
  const expected = blake3('test');

  expect(result.toString('hex')).to.equal(
    Buffer.from(expected).toString('hex'),
  );
});

test(SUITE, 'Blake3 class - reset preserves mode', () => {
  const key = new Uint8Array(32).fill(0x11);
  const hasher = new Blake3({ key });
  hasher.update('first');
  hasher.reset();
  hasher.update('second');

  const result = hasher.digest();
  const expected = blake3('second', { key });

  expect(result.toString('hex')).to.equal(
    Buffer.from(expected).toString('hex'),
  );
});

// createBlake3 factory
test(SUITE, 'createBlake3 - factory function works', () => {
  const hasher = createBlake3();
  hasher.update('test');
  const result = hasher.digest();

  expect(result.length).to.equal(32);
});

test(SUITE, 'createBlake3 - with options', () => {
  const key = new Uint8Array(32).fill(0x33);
  const hasher = createBlake3({ key });
  hasher.update('test');
  const result = hasher.digest();

  const expected = blake3('test', { key });
  expect(result.toString('hex')).to.equal(
    Buffer.from(expected).toString('hex'),
  );
});

// blake3.create shorthand
test(SUITE, 'blake3.create - shorthand for createBlake3', () => {
  const hasher = blake3.create();
  hasher.update('test');
  const result = hasher.digest();

  const expected = blake3('test');
  expect(result.toString('hex')).to.equal(
    Buffer.from(expected).toString('hex'),
  );
});

// Version check
test(SUITE, 'Blake3.getVersion - returns version string', () => {
  const version = Blake3.getVersion();
  expect(version).to.be.a('string');
  expect(version).to.match(/^\d+\.\d+\.\d+$/);
});

// Edge cases
test(SUITE, 'blake3 - handles large data', () => {
  const largeData = Buffer.alloc(1024 * 1024).fill(0x42); // 1MB
  const result = blake3(largeData);
  expect(result.length).to.equal(32);
});

test(SUITE, 'blake3 - multiple small updates equivalent to one large', () => {
  const hasher = new Blake3();
  for (let i = 0; i < 1000; i++) {
    hasher.update('x');
  }
  const streamResult = hasher.digest();

  const oneShot = blake3('x'.repeat(1000));

  expect(Buffer.from(streamResult).toString('hex')).to.equal(
    Buffer.from(oneShot).toString('hex'),
  );
});

test(SUITE, 'blake3 - empty context throws', () => {
  expect(() => blake3('test', { context: '' })).to.throw(
    /context must be a non-empty string/,
  );
});

// --- Phase 4.2: official BLAKE3 keyed_hash + derive_key KAT vectors ---
//
// Source: https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
//
// Each test_vectors.json case lists the same input bytes hashed in three
// modes (hash, keyed_hash, derive_key). The pre-existing tests above only
// exercised mode 1 (hash) against the official outputs — modes 2 and 3
// produced different bytes per construction but were never pinned to the
// published KAT outputs.
//
// The input is an N-byte prefix of the repeating sequence (0, 1, 2, ...,
// 250, 0, 1, ...) per the file's `_comment` field. The keyed_hash mode key
// is the 32-byte ASCII string `whats the Elvish word for friend`. The
// derive_key mode context is the ASCII string
// `BLAKE3 2019-12-27 16:29:52 test vectors context`. Implementations are
// expected to produce extended output but match the first 32 bytes against
// their default-length output — that's what we verify here.
const BLAKE3_KAT_KEY = new TextEncoder().encode(
  'whats the Elvish word for friend',
);
// The KAT key is 32 ASCII bytes; assert at module load so a future Unicode
// contamination of the source string can't silently shift every keyed_hash
// expected output by 1+ bytes. BLAKE3 keys must be exactly 32 bytes
// (`KEYED_HASH_KEY_LEN`) — anything else is a different MAC.
if (BLAKE3_KAT_KEY.length !== 32) {
  throw new Error(
    `BLAKE3_KAT_KEY must be 32 bytes; got ${BLAKE3_KAT_KEY.length}`,
  );
}
const BLAKE3_KAT_CONTEXT = 'BLAKE3 2019-12-27 16:29:52 test vectors context';

const buildKatInput = (len: number): Uint8Array => {
  const buf = new Uint8Array(len);
  for (let i = 0; i < len; i++) buf[i] = i % 251;
  return buf;
};

// First 32 bytes of each mode's extended output, taken verbatim from
// test_vectors.json cases for input_len ∈ {0, 1, 8, 64}.
const BLAKE3_KAT_CASES = [
  {
    input_len: 0,
    keyed_hash:
      '92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26',
    derive_key:
      '2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d',
  },
  {
    input_len: 1,
    keyed_hash:
      '6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b',
    derive_key:
      'b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c',
  },
  {
    input_len: 8,
    keyed_hash:
      'be2f5495c61cba1bb348a34948c004045e3bd4dae8f0fe82bf44d0da245a0600',
    derive_key:
      '2b166978cef14d9d438046c720519d8b1cad707e199746f1562d0c87fbd32940',
  },
  {
    input_len: 64,
    keyed_hash:
      'ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6',
    derive_key:
      'a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e',
  },
];

for (const kat of BLAKE3_KAT_CASES) {
  test(SUITE, `BLAKE3 KAT keyed_hash input_len=${kat.input_len}`, () => {
    const input = buildKatInput(kat.input_len);
    const result = blake3(input, { key: BLAKE3_KAT_KEY });
    expect(Buffer.from(result).toString('hex')).to.equal(kat.keyed_hash);
  });

  test(SUITE, `BLAKE3 KAT derive_key input_len=${kat.input_len}`, () => {
    const input = buildKatInput(kat.input_len);
    const result = blake3(input, { context: BLAKE3_KAT_CONTEXT });
    expect(Buffer.from(result).toString('hex')).to.equal(kat.derive_key);
  });
}
