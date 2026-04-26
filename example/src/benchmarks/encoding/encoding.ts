import {
  bufferToString,
  stringToBuffer,
  Buffer as CraftzdogBuffer,
} from 'react-native-quick-crypto';
// For utf16le, the native implementation could be disabled for non-Hermes runtimes or older versions of RN.
// Use the fallbacks to meature the performance without causing errors, even if it could use Buffer polyfill.
import { ab2str, binaryLikeToArrayBuffer } from 'react-native-quick-crypto';
import type { BenchFn } from '../../types/benchmarks';
import { Bench } from 'tinybench';

function ab2str_old(buf: ArrayBuffer, encoding: string = 'hex'): string {
  return CraftzdogBuffer.from(buf).toString(encoding);
}

function stringToBuffer_old(
  input: string,
  encoding: string = 'utf-8',
): ArrayBuffer {
  const buffer = CraftzdogBuffer.from(input, encoding);
  return buffer.buffer.slice(
    buffer.byteOffset,
    buffer.byteOffset + buffer.byteLength,
  );
}

// Generate test data
const generateData = (size: number, asciiOnly: boolean = true): ArrayBuffer => {
  if (size < 2 || size % 2 !== 0) {
    throw new Error('Size must be at least 2 and even');
  }
  const bytes = new Uint8Array(size); // Implicitly filled with 0
  // Fill ASCII characters in UTF-16LE code units, which can also be represented as binary/ASCII/Latin1/UTF-8
  for (let i = 0; i < bytes.length; i += 2) {
    bytes[i] = i & 0x7f;
  }
  if (!asciiOnly) {
    // \xC3\xA9 in UTF-8 or \uA9C3 in UTF-16LE
    bytes[0] = 0xc3;
    bytes[1] = 0xa9;
  }
  return bytes.buffer as ArrayBuffer;
};

const ab1MB_ascii = generateData(1024 * 1024, true);
const ab1MB = generateData(1024 * 1024, false);
const ab32B_ascii = generateData(32, true);
const ab32B = generateData(32, false);

// Pre-encode strings for decode benchmarks
const hex_1MB = bufferToString(ab1MB, 'hex');
const hex_32B = bufferToString(ab32B, 'hex');
const base64_1MB = bufferToString(ab1MB, 'base64');
const base64_32B = bufferToString(ab32B, 'base64');
const utf16le_1MB_ascii = bufferToString(ab1MB_ascii, 'utf16le');
const utf16le_32B_ascii = bufferToString(ab32B_ascii, 'utf16le');
const utf16le_1MB_non_ascii = bufferToString(ab1MB, 'utf16le');
const utf16le_32B_non_ascii = bufferToString(ab32B, 'utf16le');

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

const encode_utf16le_32b: BenchFn = () => {
  const bench = new Bench({
    name: 'utf16le encode 32B',
    iterations: 100,
    warmupIterations: 10,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      ab2str(ab32B, 'utf16le');
    })
    .add('Buffer polyfill', () => {
      ab2str_old(ab32B, 'utf16le');
    });

  return bench;
};

const encode_utf16le_1mb: BenchFn = () => {
  const bench = new Bench({
    name: 'utf16le encode 1MB',
    iterations: 10,
    warmupIterations: 2,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      ab2str(ab1MB, 'utf16le');
    })
    .add('Buffer polyfill', () => {
      ab2str_old(ab1MB, 'utf16le');
    });

  return bench;
};

const encode_utf16le_32b_ascii: BenchFn = () => {
  const bench = new Bench({
    name: 'utf16le encode 32B (ASCII only)',
    iterations: 100,
    warmupIterations: 10,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      ab2str(ab32B_ascii, 'utf16le');
    })
    .add('Buffer polyfill', () => {
      ab2str_old(ab32B_ascii, 'utf16le');
    });

  return bench;
};

const encode_utf16le_1mb_ascii: BenchFn = () => {
  const bench = new Bench({
    name: 'utf16le encode 1MB (ASCII only)',
    iterations: 10,
    warmupIterations: 2,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      ab2str(ab1MB_ascii, 'utf16le');
    })
    .add('Buffer polyfill', () => {
      ab2str_old(ab1MB_ascii, 'utf16le');
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
      stringToBuffer(hex_32B, 'hex');
    })
    .add('Buffer polyfill', () => {
      stringToBuffer_old(hex_32B, 'hex');
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
      stringToBuffer(hex_1MB, 'hex');
    })
    .add('Buffer polyfill', () => {
      stringToBuffer_old(hex_1MB, 'hex');
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

const decode_utf16le_32b: BenchFn = () => {
  const bench = new Bench({
    name: 'utf16le decode 32B',
    iterations: 100,
    warmupIterations: 10,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      binaryLikeToArrayBuffer(utf16le_32B_non_ascii, 'utf16le');
    })
    .add('Buffer polyfill', () => {
      stringToBuffer_old(utf16le_32B_non_ascii, 'utf16le');
    });

  return bench;
};

const decode_utf16le_1mb: BenchFn = () => {
  const bench = new Bench({
    name: 'utf16le decode 1MB',
    iterations: 10,
    warmupIterations: 2,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      binaryLikeToArrayBuffer(utf16le_1MB_non_ascii, 'utf16le');
    })
    .add('Buffer polyfill', () => {
      stringToBuffer_old(utf16le_1MB_non_ascii, 'utf16le');
    });

  return bench;
};

const decode_utf16le_32b_ascii: BenchFn = () => {
  const bench = new Bench({
    name: 'utf16le decode 32B (ASCII only)',
    iterations: 100,
    warmupIterations: 10,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      binaryLikeToArrayBuffer(utf16le_32B_ascii, 'utf16le');
    })
    .add('Buffer polyfill', () => {
      stringToBuffer_old(utf16le_32B_ascii, 'utf16le');
    });

  return bench;
};

const decode_utf16le_1mb_ascii: BenchFn = () => {
  const bench = new Bench({
    name: 'utf16le decode 1MB (ASCII only)',
    iterations: 10,
    warmupIterations: 2,
    time: 0,
  });

  bench
    .add('rnqc', () => {
      binaryLikeToArrayBuffer(utf16le_1MB_ascii, 'utf16le');
    })
    .add('Buffer polyfill', () => {
      stringToBuffer_old(utf16le_1MB_ascii, 'utf16le');
    });

  return bench;
};

export default [
  encode_hex_32b,
  encode_hex_1mb,
  encode_base64_32b,
  encode_base64_1mb,
  encode_utf16le_32b,
  encode_utf16le_1mb,
  encode_utf16le_32b_ascii,
  encode_utf16le_1mb_ascii,
  decode_hex_32b,
  decode_hex_1mb,
  decode_base64_32b,
  decode_base64_1mb,
  decode_utf16le_32b,
  decode_utf16le_1mb,
  decode_utf16le_32b_ascii,
  decode_utf16le_1mb_ascii,
];
