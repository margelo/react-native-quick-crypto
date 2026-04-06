import { bufferToString, stringToBuffer } from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';

const SUITE = 'utils';

// --- Helper ---

const toU8 = (ab: ArrayBuffer): Uint8Array => new Uint8Array(ab);

// --- Hex ---

test(SUITE, 'hex encode empty buffer', () => {
  const ab = new ArrayBuffer(0);
  expect(bufferToString(ab, 'hex')).to.equal('');
});

test(SUITE, 'hex decode empty string', () => {
  expect(toU8(stringToBuffer('', 'hex'))).to.deep.equal(new Uint8Array([]));
});

test(SUITE, 'hex encode known bytes', () => {
  const ab = new Uint8Array([0xde, 0xad, 0xbe, 0xef]).buffer as ArrayBuffer;
  expect(bufferToString(ab, 'hex')).to.equal('deadbeef');
});

test(SUITE, 'hex decode known string', () => {
  expect(toU8(stringToBuffer('deadbeef', 'hex'))).to.deep.equal(
    new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
  );
});

test(SUITE, 'hex roundtrip all byte values', () => {
  const bytes = new Uint8Array(256);
  for (let i = 0; i < 256; i++) bytes[i] = i;
  const ab = bytes.buffer as ArrayBuffer;
  const hex = bufferToString(ab, 'hex');
  expect(hex.length).to.equal(512);
  expect(toU8(stringToBuffer(hex, 'hex'))).to.deep.equal(bytes);
});

test(SUITE, 'hex decode is case-insensitive', () => {
  const lower = toU8(stringToBuffer('abcdef', 'hex'));
  const upper = toU8(stringToBuffer('ABCDEF', 'hex'));
  expect(lower).to.deep.equal(upper);
});

test(SUITE, 'hex decode rejects odd-length string', () => {
  expect(() => stringToBuffer('abc', 'hex')).to.throw();
});

test(SUITE, 'hex decode rejects invalid characters', () => {
  expect(() => stringToBuffer('zzzz', 'hex')).to.throw();
});

// --- Base64 ---

test(SUITE, 'base64 encode empty buffer', () => {
  const ab = new ArrayBuffer(0);
  expect(bufferToString(ab, 'base64')).to.equal('');
});

test(SUITE, 'base64 decode empty string', () => {
  expect(toU8(stringToBuffer('', 'base64'))).to.deep.equal(new Uint8Array([]));
});

test(SUITE, 'base64 encode/decode RFC 4648 test vectors', () => {
  const vectors: [string, string][] = [
    ['', ''],
    ['f', 'Zg=='],
    ['fo', 'Zm8='],
    ['foo', 'Zm9v'],
    ['foob', 'Zm9vYg=='],
    ['fooba', 'Zm9vYmE='],
    ['foobar', 'Zm9vYmFy'],
  ];
  for (const [plain, encoded] of vectors) {
    const ab = new Uint8Array(plain.split('').map(c => c.charCodeAt(0)))
      .buffer as ArrayBuffer;
    expect(bufferToString(ab, 'base64')).to.equal(encoded);
    expect(toU8(stringToBuffer(encoded, 'base64'))).to.deep.equal(
      new Uint8Array(ab),
    );
  }
});

test(SUITE, 'base64 roundtrip binary data', () => {
  const bytes = new Uint8Array([0, 1, 127, 128, 254, 255]);
  const ab = bytes.buffer as ArrayBuffer;
  const b64 = bufferToString(ab, 'base64');
  expect(toU8(stringToBuffer(b64, 'base64'))).to.deep.equal(bytes);
});

test(SUITE, 'base64 decode accepts URL-safe base64 input', () => {
  expect(toU8(stringToBuffer('-_8', 'base64'))).to.deep.equal(
    new Uint8Array([0xfb, 0xff]),
  );
});

test(
  SUITE,
  'base64 decode stops at first padding and ignores trailing data',
  () => {
    expect(toU8(stringToBuffer('Zm9v=QUJD', 'base64'))).to.deep.equal(
      new Uint8Array([0x66, 0x6f, 0x6f]),
    );
    expect(toU8(stringToBuffer('AA==BB', 'base64'))).to.deep.equal(
      new Uint8Array([0x00]),
    );
  },
);

// --- Base64url ---

test(SUITE, 'base64url encode produces URL-safe characters', () => {
  // Bytes that produce + and / in standard base64
  const bytes = new Uint8Array([0xfb, 0xff, 0xfe]);
  const ab = bytes.buffer as ArrayBuffer;
  const result = bufferToString(ab, 'base64url');
  expect(result).to.not.include('+');
  expect(result).to.not.include('/');
  expect(result).to.not.include('=');
});

test(SUITE, 'base64url roundtrip', () => {
  const bytes = new Uint8Array([0xfb, 0xff, 0xfe, 0x00, 0x42]);
  const ab = bytes.buffer as ArrayBuffer;
  const encoded = bufferToString(ab, 'base64url');
  expect(toU8(stringToBuffer(encoded, 'base64url'))).to.deep.equal(bytes);
});

test(SUITE, 'base64url decode accepts standard base64 input', () => {
  expect(toU8(stringToBuffer('+/8=', 'base64url'))).to.deep.equal(
    new Uint8Array([0xfb, 0xff]),
  );
});

test(
  SUITE,
  'base64url decode stops at first padding and ignores trailing data',
  () => {
    expect(toU8(stringToBuffer('Zm9v==QUJD', 'base64url'))).to.deep.equal(
      new Uint8Array([0x66, 0x6f, 0x6f]),
    );
    expect(toU8(stringToBuffer('TQ==QQ==', 'base64url'))).to.deep.equal(
      new Uint8Array([0x4d]),
    );
  },
);

test(SUITE, 'base64url decode accepts multiple trailing padding', () => {
  expect(toU8(stringToBuffer('TQQQ==', 'base64url'))).to.deep.equal(
    new Uint8Array([0x4d, 0x04, 0x10]),
  );
});

// --- UTF-8 ---

test(SUITE, 'utf8 encode/decode ASCII', () => {
  const str = 'hello world';
  const ab = stringToBuffer(str, 'utf-8');
  expect(bufferToString(ab, 'utf-8')).to.equal(str);
});

test(SUITE, 'utf8 encode/decode multibyte', () => {
  const str = '\u00e9\u00fc\u00f1'; // éüñ
  const ab = stringToBuffer(str, 'utf-8');
  expect(bufferToString(ab, 'utf-8')).to.equal(str);
});

test(SUITE, 'utf8 alias "utf8" works', () => {
  const str = 'test';
  const ab = stringToBuffer(str, 'utf8');
  expect(bufferToString(ab, 'utf8')).to.equal(str);
});

// --- Latin1 / Binary ---

test(
  SUITE,
  'latin1 encode: bytes 0x80-0xFF produce correct UTF-8 strings',
  () => {
    const bytes = new Uint8Array([0xe9, 0xfc, 0xf1]); // é, ü, ñ in Latin-1
    const ab = bytes.buffer as ArrayBuffer;
    const str = bufferToString(ab, 'latin1');
    expect(str).to.equal('\u00e9\u00fc\u00f1');
  },
);

test(
  SUITE,
  'latin1 decode: UTF-8 string maps each code point to one byte',
  () => {
    const str = '\u00e9\u00fc\u00f1'; // é, ü, ñ
    const ab = stringToBuffer(str, 'latin1');
    expect(toU8(ab)).to.deep.equal(new Uint8Array([0xe9, 0xfc, 0xf1]));
  },
);

test(SUITE, 'latin1 roundtrip all byte values 0x00-0xFF', () => {
  const bytes = new Uint8Array(256);
  for (let i = 0; i < 256; i++) bytes[i] = i;
  const ab = bytes.buffer as ArrayBuffer;
  const str = bufferToString(ab, 'latin1');
  const roundtripped = toU8(stringToBuffer(str, 'latin1'));
  expect(roundtripped).to.deep.equal(bytes);
});

test(SUITE, 'binary is alias for latin1 (encode)', () => {
  const bytes = new Uint8Array([0xca, 0xfe]);
  const ab = bytes.buffer as ArrayBuffer;
  expect(bufferToString(ab, 'binary')).to.equal(bufferToString(ab, 'latin1'));
});

test(SUITE, 'binary is alias for latin1 (decode)', () => {
  const str = '\u00ca\u00fe';
  expect(toU8(stringToBuffer(str, 'binary'))).to.deep.equal(
    toU8(stringToBuffer(str, 'latin1')),
  );
});

test(
  SUITE,
  'latin1 decode truncates code points above 0xFF to low byte',
  () => {
    // Node.js Buffer.from('\u0100', 'latin1') produces [0x00] (256 & 0xFF = 0)
    const ab = stringToBuffer('\u0100', 'latin1');
    expect(toU8(ab)).to.deep.equal(new Uint8Array([0x00]));
  },
);

// --- ASCII ---

test(SUITE, 'ascii encode strips high bit', () => {
  const bytes = new Uint8Array([0x48, 0xc8]); // 'H', 0xC8
  const ab = bytes.buffer as ArrayBuffer;
  const str = bufferToString(ab, 'ascii');
  expect(str.charCodeAt(0)).to.equal(0x48);
  expect(str.charCodeAt(1)).to.equal(0x48); // 0xC8 & 0x7F = 0x48
});

test(SUITE, 'ascii decode strips high bit', () => {
  const str = String.fromCharCode(0xc8); // above 0x7F
  const ab = stringToBuffer(str, 'ascii');
  expect(toU8(ab)[0]).to.equal(0x48); // 0xC8 & 0x7F = 0x48
});

test(SUITE, 'ascii roundtrip printable ASCII', () => {
  const str = 'Hello, World! 123';
  const ab = stringToBuffer(str, 'ascii');
  expect(bufferToString(ab, 'ascii')).to.equal(str);
});

// --- Unsupported encoding ---

test(SUITE, 'bufferToString throws for unsupported encoding', () => {
  const ab = new ArrayBuffer(1);
  expect(() => bufferToString(ab, 'ucs2')).to.throw();
});

test(SUITE, 'stringToBuffer throws for unsupported encoding', () => {
  expect(() => stringToBuffer('test', 'ucs2')).to.throw();
});
