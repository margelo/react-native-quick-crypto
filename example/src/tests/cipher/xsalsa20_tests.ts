import {
  Buffer,
  createCipheriv,
  createDecipheriv,
  randomFillSync,
  xsalsa20,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';

const SUITE = 'cipher';

// --- Constants and Test Data ---
const key32 = Buffer.from(
  'a8a7d6a5d4a3d2a1a09f9e9d9c8b8a89a8a7d6a5d4a3d2a1a09f9e9d9c8b8a89',
  'hex',
);
const plaintext = 'abcdefghijklmnopqrstuvwxyz';
const plaintextBuffer = Buffer.from(plaintext);

// libsodium cipher tests
test(SUITE, 'xsalsa20', () => {
  const key = new Uint8Array(key32);
  const nonce = randomFillSync(new Uint8Array(24));
  const data = new Uint8Array(plaintextBuffer);
  // encrypt
  const ciphertext = xsalsa20(key, nonce, data);
  // decrypt - must use the same nonce as encryption
  const decrypted = xsalsa20(key, nonce, ciphertext);
  // test decrypted == data
  expect(decrypted).eql(data);
});

// --- Streaming regression tests ---
//
// XSalsa20 is a stream cipher: chunked update() calls must advance the
// keystream, NOT restart it from block 0 every time. The previous
// implementation called crypto_stream_xor() on each update(), which restarted
// the keystream and produced a two-time pad if the caller streamed >1 chunk.
//
// These tests pin that fix in place by checking streaming equivalence with
// the one-shot xsalsa20() function, which is the correct reference output.

const STREAM_KEY = Buffer.from(
  'a8a7d6a5d4a3d2a1a09f9e9d9c8b8a89a8a7d6a5d4a3d2a1a09f9e9d9c8b8a89',
  'hex',
);
const STREAM_NONCE = Buffer.from(
  '111213141516171821222324252627283132333435363738',
  'hex',
);

// Block-aligned split: two 64-byte chunks (full Salsa20 blocks).
test(SUITE, 'xsalsa20 streaming equivalence — block-aligned split', () => {
  const data = Buffer.alloc(128);
  for (let i = 0; i < data.length; i++) data[i] = i & 0xff;

  const oneShot = xsalsa20(
    new Uint8Array(STREAM_KEY),
    new Uint8Array(STREAM_NONCE),
    new Uint8Array(data),
  );

  const cipher = createCipheriv('xsalsa20', STREAM_KEY, STREAM_NONCE);
  const part1 = cipher.update(data.subarray(0, 64));
  const part2 = cipher.update(data.subarray(64));
  const streamed = Buffer.concat([part1, part2, cipher.final()]);

  expect(new Uint8Array(streamed)).eql(oneShot);
});

// Mid-block split: 30 + 70 bytes, neither chunk is a multiple of 64.
test(SUITE, 'xsalsa20 streaming equivalence — mid-block split', () => {
  const data = Buffer.alloc(100);
  for (let i = 0; i < data.length; i++) data[i] = (i * 7 + 3) & 0xff;

  const oneShot = xsalsa20(
    new Uint8Array(STREAM_KEY),
    new Uint8Array(STREAM_NONCE),
    new Uint8Array(data),
  );

  const cipher = createCipheriv('xsalsa20', STREAM_KEY, STREAM_NONCE);
  const part1 = cipher.update(data.subarray(0, 30));
  const part2 = cipher.update(data.subarray(30));
  const streamed = Buffer.concat([part1, part2, cipher.final()]);

  expect(new Uint8Array(streamed)).eql(oneShot);
});

// Many small chunks crossing several block boundaries.
test(SUITE, 'xsalsa20 streaming equivalence — many small chunks', () => {
  const data = Buffer.alloc(257);
  for (let i = 0; i < data.length; i++) data[i] = (i * 13 + 5) & 0xff;

  const oneShot = xsalsa20(
    new Uint8Array(STREAM_KEY),
    new Uint8Array(STREAM_NONCE),
    new Uint8Array(data),
  );

  const cipher = createCipheriv('xsalsa20', STREAM_KEY, STREAM_NONCE);
  const chunkSizes = [1, 7, 16, 31, 33, 64, 65, 40];
  const parts: Buffer[] = [];
  let offset = 0;
  for (const size of chunkSizes) {
    const end = Math.min(offset + size, data.length);
    if (end > offset) parts.push(cipher.update(data.subarray(offset, end)));
    offset = end;
  }
  if (offset < data.length) parts.push(cipher.update(data.subarray(offset)));
  parts.push(cipher.final());
  const streamed = Buffer.concat(parts);

  expect(new Uint8Array(streamed)).eql(oneShot);
});

// Regression: identical plaintext in two consecutive update() calls MUST
// produce different ciphertexts because the keystream advances. The previous
// (buggy) implementation reset the keystream on every update(), so both
// chunks would have been bitwise identical — a two-time-pad break.
test(SUITE, 'xsalsa20 keystream advances across update() calls', () => {
  const block = Buffer.alloc(64, 0xaa);

  const cipher = createCipheriv('xsalsa20', STREAM_KEY, STREAM_NONCE);
  const c1 = cipher.update(block);
  const c2 = cipher.update(block);
  cipher.final();

  expect(c1.length).to.equal(block.length);
  expect(c2.length).to.equal(block.length);
  // If the bug returns, c1 === c2 (catastrophic).
  expect(c1.equals(c2)).to.equal(false);
});

// Edge case: a chunk that exactly drains the leftover keystream to the block
// boundary, followed by a subsequent update. Catches a regression where
// `leftover_offset` doesn't wrap to the sentinel correctly.
test(
  SUITE,
  'xsalsa20 streaming equivalence — drain-to-boundary then continue',
  () => {
    // 60 + 4 + 100 = 164 bytes. After the 60-byte chunk, leftover_offset=60;
    // the 4-byte chunk drains exactly to 64 (sentinel); the 100-byte chunk
    // must then start cleanly on a fresh block boundary.
    const data = Buffer.alloc(164);
    for (let i = 0; i < data.length; i++) data[i] = (i * 5 + 19) & 0xff;

    const oneShot = xsalsa20(
      new Uint8Array(STREAM_KEY),
      new Uint8Array(STREAM_NONCE),
      new Uint8Array(data),
    );

    const cipher = createCipheriv('xsalsa20', STREAM_KEY, STREAM_NONCE);
    const part1 = cipher.update(data.subarray(0, 60));
    const part2 = cipher.update(data.subarray(60, 64));
    const part3 = cipher.update(data.subarray(64));
    const streamed = Buffer.concat([part1, part2, part3, cipher.final()]);

    expect(new Uint8Array(streamed)).eql(oneShot);
  },
);

// Streaming round-trip: encrypt and decrypt streamed across multiple
// update() calls. Decryption is just XOR with the same keystream, so this
// also exercises the streaming state on the decrypt side.
test(SUITE, 'xsalsa20 streaming round-trip across two cipher instances', () => {
  const data = Buffer.alloc(200);
  for (let i = 0; i < data.length; i++) data[i] = (i * 11 + 17) & 0xff;

  const enc = createCipheriv('xsalsa20', STREAM_KEY, STREAM_NONCE);
  const ciphertext = Buffer.concat([
    enc.update(data.subarray(0, 50)),
    enc.update(data.subarray(50, 130)),
    enc.update(data.subarray(130)),
    enc.final(),
  ]);

  const dec = createDecipheriv('xsalsa20', STREAM_KEY, STREAM_NONCE);
  const decrypted = Buffer.concat([
    dec.update(ciphertext.subarray(0, 17)),
    dec.update(ciphertext.subarray(17, 99)),
    dec.update(ciphertext.subarray(99)),
    dec.final(),
  ]);

  expect(decrypted.equals(data)).to.equal(true);
});
