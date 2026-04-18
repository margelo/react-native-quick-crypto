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

test(SUITE, '[Node.js] Test single hex character is discarded.', () => {
  expect(toU8(stringToBuffer('A', 'hex'))).to.deep.equal(new Uint8Array([]));
});

test(
  SUITE,
  '[Node.js] Test that if a trailing character is discarded, rest of string is processed.',
  () => {
    expect(toU8(stringToBuffer('Abx', 'hex'))).to.deep.equal(
      new Uint8Array([0xab]),
    );
    expect(toU8(stringToBuffer('abc', 'hex'))).to.deep.equal(
      new Uint8Array([0xab]),
    );
  },
);

test(SUITE, '[Node.js] Test hex strings and bad hex strings', () => {
  expect(toU8(stringToBuffer('abcdxx', 'hex'))).to.deep.equal(
    new Uint8Array([0xab, 0xcd]),
  );
  expect(toU8(stringToBuffer('xxabcd', 'hex'))).to.deep.equal(
    new Uint8Array([]),
  );
  expect(toU8(stringToBuffer('cdxxab', 'hex'))).to.deep.equal(
    new Uint8Array([0xcd]),
  );

  const bytes = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    bytes[i] = i;
  }

  const hex = bufferToString(bytes.buffer as ArrayBuffer, 'hex');
  const badHex = `${hex.slice(0, 256)}xx${hex.slice(256, 510)}`;
  expect(toU8(stringToBuffer(badHex, 'hex'))).to.deep.equal(
    bytes.slice(0, 128),
  );
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

test(SUITE, "[Node.js] Test toString('base64')", () => {
  expect(bufferToString(stringToBuffer('Man', 'utf8'), 'base64')).to.equal(
    'TWFu',
  );
  expect(bufferToString(stringToBuffer('Woman', 'utf8'), 'base64')).to.equal(
    'V29tYW4=',
  );
});

test(
  SUITE,
  '[Node.js] Test that regular and URL-safe base64 both work both ways',
  () => {
    const expected = new Uint8Array([
      0xff, 0xff, 0xbe, 0xff, 0xef, 0xbf, 0xfb, 0xef, 0xff,
    ]);

    expect(toU8(stringToBuffer('//++/++/++//', 'base64'))).to.deep.equal(
      expected,
    );
    expect(toU8(stringToBuffer('__--_--_--__', 'base64'))).to.deep.equal(
      expected,
    );
    expect(toU8(stringToBuffer('//++/++/++//', 'base64url'))).to.deep.equal(
      expected,
    );
    expect(toU8(stringToBuffer('__--_--_--__', 'base64url'))).to.deep.equal(
      expected,
    );
  },
);

test(
  SUITE,
  '[Node.js] Test that regular and URL-safe base64 both work both ways with padding',
  () => {
    const expected = new Uint8Array([
      0xff, 0xff, 0xbe, 0xff, 0xef, 0xbf, 0xfb, 0xef, 0xff, 0xfb,
    ]);

    expect(toU8(stringToBuffer('//++/++/++//+w==', 'base64'))).to.deep.equal(
      expected,
    );
    expect(toU8(stringToBuffer('//++/++/++//+w==', 'base64url'))).to.deep.equal(
      expected,
    );
  },
);

test(
  SUITE,
  '[Node.js] Check that the base64 decoder ignores whitespace',
  () => {
    const quote =
      'Man is distinguished, not only by his reason, but by this ' +
      'singular passion from other animals, which is a lust ' +
      'of the mind, that by a perseverance of delight in the ' +
      'continued and indefatigable generation of knowledge, ' +
      'exceeds the short vehemence of any carnal pleasure.';
    const expected =
      'TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBi' +
      'eSB0aGlzIHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBp' +
      'cyBhIGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVs' +
      'aWdodCBpbiB0aGUgY29udGludWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24g' +
      'b2Yga25vd2xlZGdlLCBleGNlZWRzIHRoZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNh' +
      'cm5hbCBwbGVhc3VyZS4=';
    const base64flavors = ['base64', 'base64url'] as const;

    base64flavors.forEach(encoding => {
      const expectedWhite =
        `${expected.slice(0, 60)} \n` +
        `${expected.slice(60, 120)} \n` +
        `${expected.slice(120, 180)} \n` +
        `${expected.slice(180, 240)} \n` +
        `${expected.slice(240, 300)}\n` +
        `${expected.slice(300, 360)}\n`;
      const decoded = bufferToString(
        stringToBuffer(expectedWhite, encoding),
        'utf8',
      );
      expect(decoded).to.equal(quote);
    });
  },
);

test(
  SUITE,
  '[Node.js] Check that the base64 decoder ignores illegal chars',
  () => {
    const quote =
      'Man is distinguished, not only by his reason, but by this ' +
      'singular passion from other animals, which is a lust ' +
      'of the mind, that by a perseverance of delight in the ' +
      'continued and indefatigable generation of knowledge, ' +
      'exceeds the short vehemence of any carnal pleasure.';
    const expected =
      'TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBi' +
      'eSB0aGlzIHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBp' +
      'cyBhIGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVs' +
      'aWdodCBpbiB0aGUgY29udGludWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24g' +
      'b2Yga25vd2xlZGdlLCBleGNlZWRzIHRoZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNh' +
      'cm5hbCBwbGVhc3VyZS4=';
    const base64flavors = ['base64', 'base64url'] as const;

    base64flavors.forEach(encoding => {
      const expectedIllegal =
        expected.slice(0, 60) +
        ' \x80' +
        expected.slice(60, 120) +
        ' \xff' +
        expected.slice(120, 180) +
        ' \x00' +
        expected.slice(180, 240) +
        ' \x98' +
        expected.slice(240, 300) +
        '\x03' +
        expected.slice(300, 360);
      const decoded = bufferToString(
        stringToBuffer(expectedIllegal, encoding),
        'utf8',
      );
      expect(decoded).to.equal(quote);
    });
  },
);

test(SUITE, '[Node.js] Handle padding graciously, multiple-of-4 or not', () => {
  const base64flavors = ['base64', 'base64url'] as const;

  base64flavors.forEach(encoding => {
    expect(bufferToString(stringToBuffer('', encoding), 'utf8')).to.equal('');
    expect(bufferToString(stringToBuffer('K', encoding), 'utf8')).to.equal('');

    expect(bufferToString(stringToBuffer('Kg==', encoding), 'utf8')).to.equal(
      '*',
    );
    expect(bufferToString(stringToBuffer('Kio=', encoding), 'utf8')).to.equal(
      '*'.repeat(2),
    );
    expect(bufferToString(stringToBuffer('Kioq', encoding), 'utf8')).to.equal(
      '*'.repeat(3),
    );
    expect(
      bufferToString(stringToBuffer('KioqKg==', encoding), 'utf8'),
    ).to.equal('*'.repeat(4));
    expect(
      bufferToString(stringToBuffer('KioqKio=', encoding), 'utf8'),
    ).to.equal('*'.repeat(5));
    expect(
      bufferToString(stringToBuffer('KioqKioq', encoding), 'utf8'),
    ).to.equal('*'.repeat(6));
    expect(
      bufferToString(stringToBuffer('KioqKioqKg==', encoding), 'utf8'),
    ).to.equal('*'.repeat(7));
    expect(
      bufferToString(stringToBuffer('KioqKioqKio=', encoding), 'utf8'),
    ).to.equal('*'.repeat(8));
    expect(
      bufferToString(stringToBuffer('KioqKioqKioq', encoding), 'utf8'),
    ).to.equal('*'.repeat(9));
    expect(
      bufferToString(stringToBuffer('KioqKioqKioqKg==', encoding), 'utf8'),
    ).to.equal('*'.repeat(10));
    expect(
      bufferToString(stringToBuffer('KioqKioqKioqKio=', encoding), 'utf8'),
    ).to.equal('*'.repeat(11));
    expect(
      bufferToString(stringToBuffer('KioqKioqKioqKioq', encoding), 'utf8'),
    ).to.equal('*'.repeat(12));
    expect(
      bufferToString(stringToBuffer('KioqKioqKioqKioqKg==', encoding), 'utf8'),
    ).to.equal('*'.repeat(13));
    expect(
      bufferToString(stringToBuffer('KioqKioqKioqKioqKio=', encoding), 'utf8'),
    ).to.equal('*'.repeat(14));
    expect(
      bufferToString(stringToBuffer('KioqKioqKioqKioqKioq', encoding), 'utf8'),
    ).to.equal('*'.repeat(15));
    expect(
      bufferToString(
        stringToBuffer('KioqKioqKioqKioqKioqKg==', encoding),
        'utf8',
      ),
    ).to.equal('*'.repeat(16));
    expect(
      bufferToString(
        stringToBuffer('KioqKioqKioqKioqKioqKio=', encoding),
        'utf8',
      ),
    ).to.equal('*'.repeat(17));
    expect(
      bufferToString(
        stringToBuffer('KioqKioqKioqKioqKioqKioq', encoding),
        'utf8',
      ),
    ).to.equal('*'.repeat(18));
    expect(
      bufferToString(
        stringToBuffer('KioqKioqKioqKioqKioqKioqKg==', encoding),
        'utf8',
      ),
    ).to.equal('*'.repeat(19));
    expect(
      bufferToString(
        stringToBuffer('KioqKioqKioqKioqKioqKioqKio=', encoding),
        'utf8',
      ),
    ).to.equal('*'.repeat(20));

    expect(bufferToString(stringToBuffer('Kg', encoding), 'utf8')).to.equal(
      '*',
    );
    expect(bufferToString(stringToBuffer('Kio', encoding), 'utf8')).to.equal(
      '*'.repeat(2),
    );
    expect(bufferToString(stringToBuffer('KioqKg', encoding), 'utf8')).to.equal(
      '*'.repeat(4),
    );
    expect(
      bufferToString(stringToBuffer('KioqKio', encoding), 'utf8'),
    ).to.equal('*'.repeat(5));
    expect(
      bufferToString(stringToBuffer('KioqKioqKg', encoding), 'utf8'),
    ).to.equal('*'.repeat(7));
    expect(
      bufferToString(stringToBuffer('KioqKioqKio', encoding), 'utf8'),
    ).to.equal('*'.repeat(8));
    expect(
      bufferToString(stringToBuffer('KioqKioqKioqKg', encoding), 'utf8'),
    ).to.equal('*'.repeat(10));
    expect(
      bufferToString(stringToBuffer('KioqKioqKioqKio', encoding), 'utf8'),
    ).to.equal('*'.repeat(11));
    expect(
      bufferToString(stringToBuffer('KioqKioqKioqKioqKg', encoding), 'utf8'),
    ).to.equal('*'.repeat(13));
    expect(
      bufferToString(stringToBuffer('KioqKioqKioqKioqKio', encoding), 'utf8'),
    ).to.equal('*'.repeat(14));
    expect(
      bufferToString(
        stringToBuffer('KioqKioqKioqKioqKioqKg', encoding),
        'utf8',
      ),
    ).to.equal('*'.repeat(16));
    expect(
      bufferToString(
        stringToBuffer('KioqKioqKioqKioqKioqKio', encoding),
        'utf8',
      ),
    ).to.equal('*'.repeat(17));
    expect(
      bufferToString(
        stringToBuffer('KioqKioqKioqKioqKioqKioqKg', encoding),
        'utf8',
      ),
    ).to.equal('*'.repeat(19));
    expect(
      bufferToString(
        stringToBuffer('KioqKioqKioqKioqKioqKioqKio', encoding),
        'utf8',
      ),
    ).to.equal('*'.repeat(20));
  });

  expect(
    stringToBuffer('72INjkR5fchcxk9+VgdGPFJDxUBFR5/rMFsghgxADiw==', 'base64')
      .byteLength,
  ).to.equal(32);
  expect(
    stringToBuffer('72INjkR5fchcxk9-VgdGPFJDxUBFR5_rMFsghgxADiw==', 'base64url')
      .byteLength,
  ).to.equal(32);
  expect(
    stringToBuffer('72INjkR5fchcxk9+VgdGPFJDxUBFR5/rMFsghgxADiw=', 'base64')
      .byteLength,
  ).to.equal(32);
  expect(
    stringToBuffer('72INjkR5fchcxk9-VgdGPFJDxUBFR5_rMFsghgxADiw=', 'base64url')
      .byteLength,
  ).to.equal(32);
  expect(
    stringToBuffer('72INjkR5fchcxk9+VgdGPFJDxUBFR5/rMFsghgxADiw', 'base64')
      .byteLength,
  ).to.equal(32);
  expect(
    stringToBuffer('72INjkR5fchcxk9-VgdGPFJDxUBFR5_rMFsghgxADiw', 'base64url')
      .byteLength,
  ).to.equal(32);
  expect(
    stringToBuffer('w69jACy6BgZmaFvv96HG6MYksWytuZu3T1FvGnulPg==', 'base64')
      .byteLength,
  ).to.equal(31);
  expect(
    stringToBuffer('w69jACy6BgZmaFvv96HG6MYksWytuZu3T1FvGnulPg==', 'base64url')
      .byteLength,
  ).to.equal(31);
  expect(
    stringToBuffer('w69jACy6BgZmaFvv96HG6MYksWytuZu3T1FvGnulPg=', 'base64')
      .byteLength,
  ).to.equal(31);
  expect(
    stringToBuffer('w69jACy6BgZmaFvv96HG6MYksWytuZu3T1FvGnulPg=', 'base64url')
      .byteLength,
  ).to.equal(31);
  expect(
    stringToBuffer('w69jACy6BgZmaFvv96HG6MYksWytuZu3T1FvGnulPg', 'base64')
      .byteLength,
  ).to.equal(31);
  expect(
    stringToBuffer('w69jACy6BgZmaFvv96HG6MYksWytuZu3T1FvGnulPg', 'base64url')
      .byteLength,
  ).to.equal(31);
});

test(SUITE, '[Node.js] Test single base64 char encodes as 0.', () => {
  expect(toU8(stringToBuffer('A', 'base64'))).to.deep.equal(new Uint8Array([]));
});

test(
  SUITE,
  '[Node.js] Return empty output for invalid base64 with repeated leading padding (nodejs/node#3496)',
  () => {
    expect(toU8(stringToBuffer('=bad'.repeat(1e4), 'base64'))).to.deep.equal(
      new Uint8Array([]),
    );
  },
);

test(
  SUITE,
  '[Node.js] Ignore trailing whitespace in base64 input (nodejs/node#11987)',
  () => {
    expect(toU8(stringToBuffer('w0  ', 'base64'))).to.deep.equal(
      toU8(stringToBuffer('w0', 'base64')),
    );
  },
);

test(
  SUITE,
  '[Node.js] Ignore leading whitespace in base64 input (nodejs/node#13657)',
  () => {
    expect(toU8(stringToBuffer(' YWJvcnVtLg', 'base64'))).to.deep.equal(
      toU8(stringToBuffer('YWJvcnVtLg', 'base64')),
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

test(SUITE, "[Node.js] Test toString('base64url')", () => {
  expect(bufferToString(stringToBuffer('Man', 'utf8'), 'base64url')).to.equal(
    'TWFu',
  );
  expect(bufferToString(stringToBuffer('Woman', 'utf8'), 'base64url')).to.equal(
    'V29tYW4',
  );
});

test(
  SUITE,
  "[Node.js] This string encodes single '.' character in UTF-16",
  () => {
    const dot = new Uint8Array([0xff, 0xfe, 0x2e, 0x00]).buffer as ArrayBuffer;
    expect(bufferToString(dot, 'base64')).to.equal('//4uAA==');
    expect(bufferToString(dot, 'base64url')).to.equal('__4uAA');
  },
);

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

test(SUITE, '[Node.js] Test for proper UTF-8 Encoding', () => {
  expect(toU8(stringToBuffer('\u00fcber', 'utf8'))).to.deep.equal(
    new Uint8Array([195, 188, 98, 101, 114]),
  );
});

test(SUITE, '[Node.js] Test UTF-8 string includes null character', () => {
  expect(toU8(stringToBuffer('\0', 'utf8'))).to.deep.equal(
    new Uint8Array([0x00]),
  );
  expect(toU8(stringToBuffer('\0\0', 'utf8'))).to.deep.equal(
    new Uint8Array([0x00, 0x00]),
  );
});

test(
  SUITE,
  '[Node.js] Test unmatched surrogates not producing invalid utf8 output',
  () => {
    expect(toU8(stringToBuffer('ab\ud800cd', 'utf8'))).to.deep.equal(
      new Uint8Array([0x61, 0x62, 0xef, 0xbf, 0xbd, 0x63, 0x64]),
    );
  },
);

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

test(
  SUITE,
  '[Node.js] latin1 encoding should write only one byte per character.',
  () => {
    expect(
      toU8(stringToBuffer(String.fromCharCode(0xffff), 'latin1')),
    ).to.deep.equal(new Uint8Array([0xff]));
    expect(
      toU8(stringToBuffer(String.fromCharCode(0xaaee), 'latin1')),
    ).to.deep.equal(new Uint8Array([0xee]));
  },
);

test(
  SUITE,
  '[Node.js] Binary encoding should write only one byte per character.',
  () => {
    expect(
      toU8(stringToBuffer(String.fromCharCode(0xffff), 'binary')),
    ).to.deep.equal(new Uint8Array([0xff]));
    expect(
      toU8(stringToBuffer(String.fromCharCode(0xaaee), 'binary')),
    ).to.deep.equal(new Uint8Array([0xee]));
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

test(SUITE, 'ascii roundtrip printable ASCII', () => {
  const str = 'Hello, World! 123';
  const ab = stringToBuffer(str, 'ascii');
  expect(bufferToString(ab, 'ascii')).to.equal(str);
});

test(
  SUITE,
  '[Node.js] Test for proper ascii Encoding, length should be 4',
  () => {
    expect(toU8(stringToBuffer('\u00fcber', 'ascii'))).to.deep.equal(
      new Uint8Array([252, 98, 101, 114]),
    );
  },
);

test(
  SUITE,
  "[Node.js] ASCII conversion in node.js simply masks off the high bits, it doesn't do transliteration.",
  () => {
    expect(
      bufferToString(stringToBuffer('h\u00e9rit\u00e9', 'utf8'), 'ascii'),
    ).to.equal('hC)ritC)');
  },
);

test(
  SUITE,
  '[Node.js] Test ASCII decoding of UTF-8 multibyte characters at every byte offset.',
  () => {
    const input =
      'C\u2019est, graphiquement, la r\u00e9union d\u2019un accent aigu ' +
      'et d\u2019un accent grave.';

    const expected =
      'Cb\u0000\u0019est, graphiquement, la rC)union ' +
      'db\u0000\u0019un accent aigu et db\u0000\u0019un ' +
      'accent grave.';

    const bytes = toU8(stringToBuffer(input, 'utf8'));

    for (let i = 0; i < expected.length; ++i) {
      const slice = bytes.slice(i);
      expect(bufferToString(slice.buffer as ArrayBuffer, 'ascii')).to.equal(
        expected.slice(i),
      );
    }
  },
);

// --- Unsupported encoding ---

test(SUITE, 'bufferToString throws for unsupported encoding', () => {
  const ab = new ArrayBuffer(1);
  expect(() => bufferToString(ab, 'ucs2')).to.throw();
});

test(SUITE, 'stringToBuffer throws for unsupported encoding', () => {
  expect(() => stringToBuffer('test', 'ucs2')).to.throw();
});
