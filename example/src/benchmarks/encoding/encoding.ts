import {
  bufferToString,
  stringToBuffer,
  ab2str_old,
  stringToBuffer_old,
} from 'react-native-quick-crypto';
import type { BenchFn } from '../../types/benchmarks';
import { Bench } from 'tinybench';

// Generate test data
const generate1MB = (): ArrayBuffer => {
  const bytes = new Uint8Array(1024 * 1024);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = i & 0xff;
  }
  return bytes.buffer as ArrayBuffer;
};

const ab1MB = generate1MB();
const ab32B = new Uint8Array(32).buffer as ArrayBuffer; // typical hash digest size
// Fill 32B with non-zero data
new Uint8Array(ab32B).set([
  0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89,
  0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22,
  0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
]);

// Pre-encode strings for decode benchmarks
const hex1MB = bufferToString(ab1MB, 'hex');
const base64_1MB = bufferToString(ab1MB, 'base64');
const hex32B = bufferToString(ab32B, 'hex');
const base64_32B = bufferToString(ab32B, 'base64');

// --- Encode benchmarks (ArrayBuffer → string) ---

const encode_hex_32b: BenchFn = () => {
  const bench = new Bench({
    name: 'hex encode 32B (digest size)',
    iterations: 100,
    warmupIterations: 10,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      bufferToString(ab32B, 'hex');
    })
    .add('Buffer polyfill', () => {
      ab2str_old(ab32B, 'hex');
    });

  return bench;
};

const encode_hex_1mb: BenchFn = () => {
  const bench = new Bench({
    name: 'hex encode 1MB',
    iterations: 10,
    warmupIterations: 2,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      bufferToString(ab1MB, 'hex');
    })
    .add('Buffer polyfill', () => {
      ab2str_old(ab1MB, 'hex');
    });

  return bench;
};

const encode_base64_32b: BenchFn = () => {
  const bench = new Bench({
    name: 'base64 encode 32B (digest size)',
    iterations: 100,
    warmupIterations: 10,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      bufferToString(ab32B, 'base64');
    })
    .add('Buffer polyfill', () => {
      ab2str_old(ab32B, 'base64');
    });

  return bench;
};

const encode_base64_1mb: BenchFn = () => {
  const bench = new Bench({
    name: 'base64 encode 1MB',
    iterations: 10,
    warmupIterations: 2,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      bufferToString(ab1MB, 'base64');
    })
    .add('Buffer polyfill', () => {
      ab2str_old(ab1MB, 'base64');
    });

  return bench;
};

// --- Decode benchmarks (string → ArrayBuffer) ---

const decode_hex_32b: BenchFn = () => {
  const bench = new Bench({
    name: 'hex decode 32B',
    iterations: 100,
    warmupIterations: 10,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      stringToBuffer(hex32B, 'hex');
    })
    .add('Buffer polyfill', () => {
      stringToBuffer_old(hex32B, 'hex');
    });

  return bench;
};

const decode_hex_1mb: BenchFn = () => {
  const bench = new Bench({
    name: 'hex decode 1MB',
    iterations: 10,
    warmupIterations: 2,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      stringToBuffer(hex1MB, 'hex');
    })
    .add('Buffer polyfill', () => {
      stringToBuffer_old(hex1MB, 'hex');
    });

  return bench;
};

const decode_base64_32b: BenchFn = () => {
  const bench = new Bench({
    name: 'base64 decode 32B',
    iterations: 100,
    warmupIterations: 10,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      stringToBuffer(base64_32B, 'base64');
    })
    .add('Buffer polyfill', () => {
      stringToBuffer_old(base64_32B, 'base64');
    });

  return bench;
};

const decode_base64_1mb: BenchFn = () => {
  const bench = new Bench({
    name: 'base64 decode 1MB',
    iterations: 10,
    warmupIterations: 2,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      stringToBuffer(base64_1MB, 'base64');
    })
    .add('Buffer polyfill', () => {
      stringToBuffer_old(base64_1MB, 'base64');
    });

  return bench;
};

export default [
  encode_hex_32b,
  encode_hex_1mb,
  encode_base64_32b,
  encode_base64_1mb,
  decode_hex_32b,
  decode_hex_1mb,
  decode_base64_32b,
  decode_base64_1mb,
];
