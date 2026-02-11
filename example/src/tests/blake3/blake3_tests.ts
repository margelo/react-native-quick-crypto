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
