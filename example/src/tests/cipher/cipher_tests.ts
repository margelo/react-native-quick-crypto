import {
  Buffer,
  getCipherInfo,
  getCiphers,
  createCipheriv,
  createDecipheriv,
  randomFillSync,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';
import { roundTrip, roundTripAuth } from './roundTrip';

const SUITE = 'cipher';

// --- Constants and Test Data ---
const key16 = Buffer.from('a8a7d6a5d4a3d2a1a09f9e9d9c8b8a89', 'hex');
const key32 = Buffer.from(
  'a8a7d6a5d4a3d2a1a09f9e9d9c8b8a89a8a7d6a5d4a3d2a1a09f9e9d9c8b8a89',
  'hex',
);
const iv16 = randomFillSync(new Uint8Array(16));
const iv12 = randomFillSync(new Uint8Array(12)); // Common IV size for GCM/CCM/OCB
const iv = Buffer.from(iv16);
const aad = Buffer.from('Additional Authenticated Data');
const plaintext = 'abcdefghijklmnopqrstuvwxyz';
const plaintextBuffer = Buffer.from(plaintext);

// --- Tests ---
test(SUITE, 'valid algorithm', () => {
  expect(() => {
    createCipheriv('aes-128-cbc', Buffer.alloc(16), Buffer.alloc(16), {});
  }).to.not.throw();
});

test(SUITE, 'invalid algorithm', () => {
  expect(() => {
    createCipheriv('aes-128-boorad', Buffer.alloc(16), Buffer.alloc(16), {});
  }).to.throw('Unsupported or unknown cipher type: aes-128-boorad');
});

test(SUITE, 'strings', () => {
  // Strings are interpreted as UTF-8 bytes by createCipheriv, so use
  // 16-char ASCII so the byte-length matches aes-128-cbc's (16, 16) sizes.
  roundTrip(
    'aes-128-cbc',
    'YELLOW SUBMARINE',
    '0123456789ABCDEF',
    plaintextBuffer,
  );
});

test(SUITE, 'buffers', () => {
  roundTrip('aes-128-cbc', key16, iv, plaintextBuffer);
});

// AES-CBC-HMAC ciphers are TLS-only and require special ctrl functions.
// They also depend on specific hardware (AES-NI) and may not be available
// on all platforms (e.g., CI emulators). Skip them in tests.
// See: https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_cbc_hmac_sha1.html
const TLS_ONLY_CIPHERS = [
  'AES-128-CBC-HMAC-SHA1',
  'AES-128-CBC-HMAC-SHA256',
  'AES-256-CBC-HMAC-SHA1',
  'AES-256-CBC-HMAC-SHA256',
];

// loop through each cipher and test roundtrip
const allCiphers = getCiphers().filter(
  c => !TLS_ONLY_CIPHERS.includes(c.toUpperCase()),
);
allCiphers.forEach(cipherName => {
  test(SUITE, cipherName, () => {
    try {
      // Determine correct key length. Order matters: DES-EDE3 must be
      // checked before DES-EDE because `'DES-EDE3-CBC'.includes('DES-EDE')`
      // is also true. AES / ARIA / CAMELLIA carry their key size in the name.
      let keyLen: number;
      if (cipherName.includes('DES-EDE3')) {
        keyLen = 24; // 3-key 3DES
      } else if (cipherName.includes('DES-EDE')) {
        keyLen = 16; // 2-key 3DES
      } else if (cipherName.includes('128')) {
        keyLen = 16;
      } else if (cipherName.includes('192')) {
        keyLen = 24;
      } else {
        keyLen = 32; // Default to 256-bit
      }
      let testKey: Uint8Array;
      if (cipherName.includes('XTS')) {
        keyLen *= 2; // XTS requires double length key
        testKey = randomFillSync(new Uint8Array(keyLen));
        const keyBuffer = Buffer.from(testKey); // Create Buffer once
        // Ensure key halves are not identical for XTS
        const half = keyLen / 2;
        while (
          keyBuffer.subarray(0, half).equals(keyBuffer.subarray(half, keyLen))
        ) {
          testKey = randomFillSync(new Uint8Array(keyLen));
          Object.assign(keyBuffer, Buffer.from(testKey));
        }
      } else {
        testKey = randomFillSync(new Uint8Array(keyLen));
      }

      // Select IV size. AEAD modes get the canonical 12-byte nonce; for
      // every other cipher we ask the runtime what IV length the cipher
      // expects (0 for ECB, 8 for DES-family 64-bit blocks, 16 for AES,
      // …). This keeps the loop generic instead of hard-coding sizes.
      let testIv: Uint8Array;
      if (
        cipherName.includes('GCM') ||
        cipherName.includes('OCB') ||
        cipherName.includes('CCM') ||
        cipherName.includes('Poly1305')
      ) {
        testIv = iv12;
      } else {
        const ivLen = getCipherInfo(cipherName)?.ivLength ?? 0;
        testIv =
          ivLen === 0
            ? new Uint8Array(0)
            : randomFillSync(new Uint8Array(ivLen));
      }

      // Create key and iv as Buffers for the roundtrip functions
      const key = Buffer.from(testKey);
      const iv = Buffer.from(testIv);

      // Determine if authenticated mode and call appropriate roundtrip helper
      if (
        cipherName.includes('GCM') ||
        cipherName.includes('CCM') ||
        cipherName.includes('OCB') ||
        cipherName.includes('Poly1305') ||
        cipherName.includes('SIV') // SIV modes also use auth
      ) {
        roundTripAuth(cipherName, key, iv, plaintextBuffer, aad);
      } else {
        roundTrip(cipherName, key, iv, plaintextBuffer);
      }
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      expect.fail(`Cipher ${cipherName} threw an error: ${message}`);
    }
  });
});

test(SUITE, 'GCM getAuthTag', () => {
  const cipher = createCipheriv('aes-256-gcm', key32, iv12);
  cipher.setAAD(aad);
  cipher.update(plaintextBuffer);
  cipher.final();

  const tag = cipher.getAuthTag();
  expect(tag.length).to.equal(16);
});

// Issue #798: decipher.final() should throw on incorrect key for aes-256-gcm
test(SUITE, 'GCM wrong key throws error (issue #798)', () => {
  const correctKey = Buffer.from('a'.repeat(64), 'hex'); // 32 bytes
  const wrongKey = Buffer.from('b'.repeat(64), 'hex'); // different 32 bytes
  const testIv = randomFillSync(new Uint8Array(12));
  const testPlaintext = Buffer.from('test data for encryption');
  const testAad = Buffer.from('additional data');

  // Encrypt with correct key
  const cipher = createCipheriv('aes-256-gcm', correctKey, Buffer.from(testIv));
  cipher.setAAD(testAad);
  const encrypted = Buffer.concat([
    cipher.update(testPlaintext),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // Decrypt with wrong key - should throw on final()
  const decipher = createDecipheriv(
    'aes-256-gcm',
    wrongKey,
    Buffer.from(testIv),
  );
  decipher.setAAD(testAad);
  decipher.setAuthTag(authTag);
  decipher.update(encrypted);

  expect(() => decipher.final()).to.throw();
});

// --- String encoding tests (issue #945) ---

test(SUITE, 'Buffer concat vs string concat produce same result', () => {
  const testKey = Buffer.from(
    'KTnGEDonslhj/qGvf6rj4HSnO32T7dvjAs5PntTDB0s=',
    'base64',
  );
  const testIv = Buffer.from('2pXx2krk1wU8RI6AQjuPUg==', 'base64');
  const text = 'this is a test.';

  // Buffer concat approach
  const cipher1 = createCipheriv('aes-256-cbc', testKey, testIv);
  const bufResult = Buffer.concat([
    cipher1.update(Buffer.from(text, 'utf8')),
    cipher1.final(),
  ]).toString('base64');

  // String concat approach (fresh cipher)
  const cipher2 = createCipheriv('aes-256-cbc', testKey, testIv);
  const strResult =
    cipher2.update(text, 'utf8', 'base64') + cipher2.final('base64');

  expect(bufResult).to.equal(strResult);
});

test(SUITE, 'base64 string encoding with multi-block plaintext', () => {
  const testKey = Buffer.from(
    'KTnGEDonslhj/qGvf6rj4HSnO32T7dvjAs5PntTDB0s=',
    'base64',
  );
  const testIv = Buffer.from('2pXx2krk1wU8RI6AQjuPUg==', 'base64');
  // 32 bytes = 2 AES blocks; update() returns 32 bytes, 32 % 3 = 2 remainder
  const text = 'A'.repeat(32);

  const cipher1 = createCipheriv('aes-256-cbc', testKey, testIv);
  const bufResult = Buffer.concat([
    cipher1.update(Buffer.from(text, 'utf8')),
    cipher1.final(),
  ]).toString('base64');

  const cipher2 = createCipheriv('aes-256-cbc', testKey, testIv);
  const strResult =
    cipher2.update(text, 'utf8', 'base64') + cipher2.final('base64');

  expect(bufResult).to.equal(strResult);
});

test(SUITE, 'base64 encoding at exactly one block boundary', () => {
  // 16 bytes = exactly one AES block; update() returns 16 bytes, 16 % 3 = 1
  const text = 'A'.repeat(16);

  const cipher1 = createCipheriv('aes-128-cbc', key16, iv);
  const bufResult = Buffer.concat([
    cipher1.update(Buffer.from(text, 'utf8')),
    cipher1.final(),
  ]).toString('base64');

  const cipher2 = createCipheriv('aes-128-cbc', key16, iv);
  const strResult =
    cipher2.update(text, 'utf8', 'base64') + cipher2.final('base64');

  expect(bufResult).to.equal(strResult);
});

test(SUITE, 'base64 encoding encrypt/decrypt roundtrip with long input', () => {
  const longText = 'The quick brown fox jumps over the lazy dog. '.repeat(5);

  const cipher = createCipheriv('aes-256-cbc', key32, iv);
  const encrypted =
    cipher.update(longText, 'utf8', 'base64') + cipher.final('base64');

  const decipher = createDecipheriv('aes-256-cbc', key32, iv);
  const decrypted =
    decipher.update(encrypted, 'base64', 'utf8') + decipher.final('utf8');

  expect(decrypted).to.equal(longText);
});

test(SUITE, 'update with hex input and output encoding', () => {
  const cipher1 = createCipheriv('aes-128-cbc', key16, iv);
  const bufResult = Buffer.concat([
    cipher1.update(plaintextBuffer),
    cipher1.final(),
  ]).toString('hex');

  const cipher2 = createCipheriv('aes-128-cbc', key16, iv);
  const hexResult =
    cipher2.update(plaintext, 'utf8', 'hex') + cipher2.final('hex');

  expect(bufResult).to.equal(hexResult);
});

test(SUITE, 'update with hex input decryption', () => {
  // Encrypt
  const cipher = createCipheriv('aes-128-cbc', key16, iv);
  const encrypted =
    cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');

  // Decrypt using hex input encoding
  const decipher = createDecipheriv('aes-128-cbc', key16, iv);
  const decrypted =
    decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');

  expect(decrypted).to.equal(plaintext);
});

test(SUITE, 'update with hex encoding roundtrip (aes-256-cbc)', () => {
  // Encrypt
  const cipher = createCipheriv('aes-256-cbc', key32, iv);
  const encrypted =
    cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');

  // Decrypt
  const decipher = createDecipheriv('aes-256-cbc', key32, iv);
  const decrypted =
    decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');

  expect(decrypted).to.equal(plaintext);
});

// --- Cipher state violation tests ---

test(SUITE, 'update after final throws', () => {
  const cipher = createCipheriv('aes-128-cbc', key16, iv);
  cipher.update(plaintextBuffer);
  cipher.final();

  expect(() => cipher.update(plaintextBuffer)).to.throw();
});

test(SUITE, 'final called twice throws', () => {
  const cipher = createCipheriv('aes-128-cbc', key16, iv);
  cipher.update(plaintextBuffer);
  cipher.final();

  expect(() => cipher.final()).to.throw();
});

test(SUITE, 'decipher update after final throws', () => {
  // First encrypt something
  const cipher = createCipheriv('aes-128-cbc', key16, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintextBuffer),
    cipher.final(),
  ]);

  // Decrypt and then try to reuse
  const decipher = createDecipheriv('aes-128-cbc', key16, iv);
  decipher.update(encrypted);
  decipher.final();

  expect(() => decipher.update(encrypted)).to.throw();
});

test(SUITE, 'cipher works after re-init (createCipheriv)', () => {
  // First use
  const cipher1 = createCipheriv('aes-128-cbc', key16, iv);
  const enc1 = Buffer.concat([
    cipher1.update(plaintextBuffer),
    cipher1.final(),
  ]);

  // Second use with same params should produce identical result
  const cipher2 = createCipheriv('aes-128-cbc', key16, iv);
  const enc2 = Buffer.concat([
    cipher2.update(plaintextBuffer),
    cipher2.final(),
  ]);

  expect(enc1.toString('hex')).to.equal(enc2.toString('hex'));

  // Verify decryption still works
  const decipher = createDecipheriv('aes-128-cbc', key16, iv);
  const decrypted = Buffer.concat([decipher.update(enc2), decipher.final()]);
  expect(decrypted.toString('utf8')).to.equal(plaintext);
});

test(SUITE, 'GCM tampered ciphertext throws error', () => {
  const testKey = Buffer.from(randomFillSync(new Uint8Array(32)));
  const testIv = randomFillSync(new Uint8Array(12));
  const testPlaintext = Buffer.from('test data');
  const testAad = Buffer.from('additional data');

  const cipher = createCipheriv('aes-256-gcm', testKey, Buffer.from(testIv));
  cipher.setAAD(testAad);
  const encrypted = Buffer.concat([
    cipher.update(testPlaintext),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // Tamper with ciphertext
  encrypted[0] = encrypted[0]! ^ 1;

  const decipher = createDecipheriv(
    'aes-256-gcm',
    testKey,
    Buffer.from(testIv),
  );
  decipher.setAAD(testAad);
  decipher.setAuthTag(authTag);
  decipher.update(encrypted);

  expect(() => decipher.final()).to.throw();
});

test(SUITE, 'GCM tampered auth tag throws error', () => {
  const testKey = Buffer.from(randomFillSync(new Uint8Array(32)));
  const testIv = randomFillSync(new Uint8Array(12));
  const testPlaintext = Buffer.from('test data');
  const testAad = Buffer.from('additional data');

  const cipher = createCipheriv('aes-256-gcm', testKey, Buffer.from(testIv));
  cipher.setAAD(testAad);
  const encrypted = Buffer.concat([
    cipher.update(testPlaintext),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // Tamper with auth tag
  authTag[0] = authTag[0]! ^ 1;

  const decipher = createDecipheriv(
    'aes-256-gcm',
    testKey,
    Buffer.from(testIv),
  );
  decipher.setAAD(testAad);
  decipher.setAuthTag(authTag);
  decipher.update(encrypted);

  expect(() => decipher.final()).to.throw();
});

// --- setAAD byte-offset regression tests ---
// Pre-fix, setAAD passed `buffer.buffer` to native, ignoring byteOffset /
// byteLength on sliced Buffers. That meant a sliced AAD authenticated the
// wrong bytes — a silent AEAD integrity violation.

test(
  SUITE,
  'GCM setAAD with sliced Buffer authenticates the slice (not backing)',
  () => {
    const testKey = Buffer.from(randomFillSync(new Uint8Array(32)));
    const testIv = randomFillSync(new Uint8Array(12));
    const testPlaintext = Buffer.from('test data for AAD slice');

    // Build a backing buffer with a known 16-byte AAD region in the middle and
    // distinct surrounding bytes. The cipher must only authenticate the slice.
    const backing = Buffer.concat([
      Buffer.from('PREFIX_NOISE_'),
      Buffer.from('aad-payload-1234'), // 16-byte AAD window
      Buffer.from('_SUFFIX_NOISE'),
    ]);
    const aadSlice = backing.subarray(13, 13 + 16);
    expect(aadSlice.byteLength).to.equal(16);
    expect(aadSlice.toString('utf8')).to.equal('aad-payload-1234');

    // Encrypt with the sliced AAD.
    const cipher = createCipheriv('aes-256-gcm', testKey, Buffer.from(testIv));
    cipher.setAAD(aadSlice);
    const encrypted = Buffer.concat([
      cipher.update(testPlaintext),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    // Decrypt with a freshly-constructed Buffer carrying the same 16 logical
    // bytes — no surrounding noise, byteOffset = 0. If setAAD honors the
    // slice on encrypt, this must verify successfully.
    const aadStandalone = Buffer.from('aad-payload-1234');
    const decipher = createDecipheriv(
      'aes-256-gcm',
      testKey,
      Buffer.from(testIv),
    );
    decipher.setAAD(aadStandalone);
    decipher.setAuthTag(authTag);
    const plaintextOut = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);
    expect(plaintextOut.toString('utf8')).to.equal(
      testPlaintext.toString('utf8'),
    );
  },
);

test(
  SUITE,
  'GCM setAAD with sliced Buffer rejects wrong AAD on decrypt',
  () => {
    // Mirror of the previous test but supplies different AAD bytes on decrypt
    // — must fail authentication.
    const testKey = Buffer.from(randomFillSync(new Uint8Array(32)));
    const testIv = randomFillSync(new Uint8Array(12));
    const testPlaintext = Buffer.from('test data for AAD slice');

    const backing = Buffer.concat([
      Buffer.from('PREFIX_NOISE_'),
      Buffer.from('aad-payload-1234'),
      Buffer.from('_SUFFIX_NOISE'),
    ]);
    const aadSlice = backing.subarray(13, 13 + 16);

    const cipher = createCipheriv('aes-256-gcm', testKey, Buffer.from(testIv));
    cipher.setAAD(aadSlice);
    const encrypted = Buffer.concat([
      cipher.update(testPlaintext),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    // Decrypt with WRONG AAD bytes — must throw on final().
    const wrongAad = Buffer.from('aad-payload-DIFF');
    const decipher = createDecipheriv(
      'aes-256-gcm',
      testKey,
      Buffer.from(testIv),
    );
    decipher.setAAD(wrongAad);
    decipher.setAuthTag(authTag);
    decipher.update(encrypted);
    expect(() => decipher.final()).to.throw();
  },
);

// --- getUIntOption type-safety regression (Phase 1.4) ---
//
// Ensure the AEAD `authTagLength` option is validated at the JS boundary.
// The previous implementation used `Record<string, any>` and the cryptic
// `value >>> 0 !== value` check; the typed replacement throws RangeError
// with a clear "must be a non-negative 32-bit integer" message.

test(SUITE, 'createCipheriv: rejects negative authTagLength', () => {
  expect(() => {
    createCipheriv('aes-256-gcm', key32, iv12, {
      authTagLength: -1,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any);
  }).to.throw(/non-negative/i);
});

test(SUITE, 'createCipheriv: rejects NaN authTagLength', () => {
  expect(() => {
    createCipheriv('aes-256-gcm', key32, iv12, {
      authTagLength: NaN,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any);
  }).to.throw(/non-negative/i);
});

test(SUITE, 'createCipheriv: rejects fractional authTagLength', () => {
  expect(() => {
    createCipheriv('aes-256-gcm', key32, iv12, {
      authTagLength: 12.5,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any);
  }).to.throw(/non-negative/i);
});

test(
  SUITE,
  'createCipheriv: missing authTagLength still defaults to 16',
  () => {
    // Sanity check that the new helper's `?? 16` default still kicks in.
    expect(() => {
      createCipheriv('aes-256-gcm', key32, iv12, {});
    }).to.not.throw();
  },
);

// --- TS-layer cipher param validation regression (Phase 3.1) ---
//
// Pre-fix, wrong key / iv lengths reached C++ before being rejected, producing
// confusing OpenSSL error strings. The TS layer now pre-validates against
// getCipherInfo() (or a small libsodium table) and throws a clear
// `RangeError: Invalid {key,iv} length …` before the native call.

test(SUITE, 'createCipheriv: rejects empty algorithm', () => {
  expect(() => {
    createCipheriv('', key32, iv16);
  }).to.throw(TypeError, /non-empty string/);
});

test(SUITE, 'createCipheriv: rejects unknown algorithm', () => {
  expect(() => {
    createCipheriv('aes-128-boorad', key16, iv16);
  }).to.throw(TypeError, /Unsupported or unknown cipher/);
});

test(SUITE, 'createCipheriv: rejects too-short key for aes-256-cbc', () => {
  // Pass a 128-bit key to a 256-bit cipher.
  expect(() => {
    createCipheriv('aes-256-cbc', key16, iv16);
  }).to.throw(RangeError, /Invalid key length 16/);
});

test(SUITE, 'createCipheriv: rejects too-long key for aes-128-cbc', () => {
  // Pass a 256-bit key to a 128-bit cipher.
  expect(() => {
    createCipheriv('aes-128-cbc', key32, iv16);
  }).to.throw(RangeError, /Invalid key length 32/);
});

test(SUITE, 'createCipheriv: rejects empty key', () => {
  expect(() => {
    createCipheriv('aes-128-cbc', Buffer.alloc(0), iv16);
  }).to.throw(RangeError, /key length 0/);
});

test(SUITE, 'createCipheriv: rejects wrong iv length for aes-128-cbc', () => {
  // CBC requires a 16-byte IV. 12 bytes (a GCM-style IV) must be rejected.
  expect(() => {
    createCipheriv('aes-128-cbc', key16, iv12);
  }).to.throw(RangeError, /Invalid iv length 12/);
});

test(SUITE, 'createCipheriv: rejects wrong iv length for aes-128-ccm', () => {
  // CCM accepts 7..13 byte IVs. 16 bytes must be rejected.
  expect(() => {
    createCipheriv('aes-128-ccm', key16, iv16, { authTagLength: 16 });
  }).to.throw(RangeError, /Invalid iv length 16/);
});

test(
  SUITE,
  'createCipheriv: accepts variable iv length for aes-256-gcm',
  () => {
    // GCM accepts a wide range of IV lengths.
    expect(() => {
      createCipheriv('aes-256-gcm', key32, iv16);
    }).to.not.throw();
    expect(() => {
      createCipheriv('aes-256-gcm', key32, iv12);
    }).to.not.throw();
  },
);

test(SUITE, 'createDecipheriv: rejects too-long key for aes-128-cbc', () => {
  expect(() => {
    createDecipheriv('aes-128-cbc', key32, iv16);
  }).to.throw(RangeError, /Invalid key length 32/);
});

test(SUITE, 'createCipheriv: rejects wrong xsalsa20 key length', () => {
  expect(() => {
    createCipheriv('xsalsa20', key16, randomFillSync(new Uint8Array(24)));
  }).to.throw(RangeError, /Invalid key length 16 .* xsalsa20/);
});

test(SUITE, 'createCipheriv: rejects wrong xsalsa20 nonce length', () => {
  expect(() => {
    createCipheriv('xsalsa20', key32, iv16);
  }).to.throw(RangeError, /Invalid nonce length 16 .* xsalsa20/);
});

// Phase 3.6 regression: stream _transform / _flush errors (e.g. AEAD
// auth-tag mismatch on Decipher.final()) must surface as 'error' events
// rather than throwing through the Transform plumbing. Drive each path
// through the public stream API.

test(
  SUITE,
  'Decipher: auth-tag mismatch surfaces as "error" event',
  async () => {
    // Encrypt to obtain a valid (key, iv, tag) triple, then tamper with the
    // auth tag so Decipher.final() rejects authentication.
    const testKey = Buffer.from(randomFillSync(new Uint8Array(32)));
    const testIv = randomFillSync(new Uint8Array(12));
    const cipher = createCipheriv('aes-256-gcm', testKey, Buffer.from(testIv));
    cipher.setAAD(aad);
    const encrypted = Buffer.concat([
      cipher.update(plaintextBuffer),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    tag[0] = tag[0]! ^ 0xff;

    const decipher = createDecipheriv(
      'aes-256-gcm',
      testKey,
      Buffer.from(testIv),
    );
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    decipher.update(encrypted);

    const error = await new Promise<Error>(resolve => {
      decipher.once('error', resolve);
      decipher.end(); // triggers _flush → final() → tag mismatch
    });
    expect(error).to.be.instanceOf(Error);
  },
);

test(SUITE, 'Cipher: _transform error surfaces as "error" event', async () => {
  const cipher = createCipheriv('aes-128-cbc', key16, iv16);
  cipher.update(plaintextBuffer);
  cipher.final(); // finalize — next update() throws

  const error = await new Promise<Error>(resolve => {
    cipher.once('error', resolve);
    cipher.write('after final');
  });
  expect(error).to.be.instanceOf(Error);
});

// --- Phase 4.1: NIST AEAD Known-Answer Tests ---
//
// Until now the cipher suite only verified round-trip identity (encrypt →
// decrypt yields the original plaintext) for every cipher returned by
// `getCiphers()`. That catches obvious wiring bugs but does NOT pin the
// ciphertext or the auth tag bytes against the published NIST / IETF
// reference values. A subtle bug — e.g. CCM's CTR formatting, GCM's GHASH
// byte order, OCB's offset chaining — could pass round-trip and still
// produce ciphertext that no other AES-GCM/CCM/OCB implementation can
// decrypt. The KATs below close that gap.
//
// Sources (each `name` field cites the document section):
//   AES-GCM — NIST GCM Test Vectors (Joux/McGrew "The Galois/Counter Mode")
//             Test Cases 2, 3, 4 — also in Section 2.5 of the spec.
//   AES-CCM — NIST SP 800-38C Appendix C (C.1 / C.2 / C.3).
//   AES-OCB — RFC 7253 §A — canonical key 0..0F, plaintext 0..N-1.

interface AeadKat {
  name: string;
  cipher: string;
  key: string; // hex
  iv: string; // hex
  aad: string; // hex (may be empty)
  plaintext: string; // hex (may be empty)
  ciphertext: string; // hex (may be empty)
  tag: string; // hex (auth tag returned by getAuthTag)
  authTagLength?: number; // bytes; defaults to tag.length / 2
}

const AEAD_KATS: AeadKat[] = [
  // --- AES-GCM, NIST GCM spec test cases ---
  // Test Case 2: K=0...0, IV=0...0, AAD empty, P=16 zero bytes
  {
    name: 'AES-GCM NIST Test Case 2',
    cipher: 'aes-128-gcm',
    key: '00000000000000000000000000000000',
    iv: '000000000000000000000000',
    aad: '',
    plaintext: '00000000000000000000000000000000',
    ciphertext: '0388dace60b6a392f328c2b971b2fe78',
    tag: 'ab6e47d42cec13bdf53a67b21257bddf',
  },
  // Test Case 3: K = "feffe9928665731c6d6a8f9467308308", IV = "cafebabefacedbaddecaf888"
  {
    name: 'AES-GCM NIST Test Case 3',
    cipher: 'aes-128-gcm',
    key: 'feffe9928665731c6d6a8f9467308308',
    iv: 'cafebabefacedbaddecaf888',
    aad: '',
    plaintext:
      'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
    ciphertext:
      '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985',
    tag: '4d5c2af327cd64a62cf35abd2ba6fab4',
  },
  // Test Case 4: same K/IV as TC3, but with AAD and shorter (60-byte) P
  {
    name: 'AES-GCM NIST Test Case 4',
    cipher: 'aes-128-gcm',
    key: 'feffe9928665731c6d6a8f9467308308',
    iv: 'cafebabefacedbaddecaf888',
    aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
    plaintext:
      'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
    ciphertext:
      '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091',
    tag: '5bc94fbc3221a5db94fae95ae7121a47',
  },
  // --- AES-CCM, NIST SP 800-38C Appendix C ---
  // C.1: K=40-..-4F (16 B), N=10..16 (7 B), A=0..7 (8 B), P=20..2E (4 B), Tlen=4, Mlen=4 ⇒ tag 4 B
  {
    name: 'AES-CCM SP 800-38C C.1',
    cipher: 'aes-128-ccm',
    key: '404142434445464748494a4b4c4d4e4f',
    iv: '10111213141516',
    aad: '0001020304050607',
    plaintext: '20212223',
    ciphertext: '7162015b',
    tag: '4dac255d',
    authTagLength: 4,
  },
  // C.2: same K, N=10..17 (8 B), A=0..F (16 B), P=20..2F (16 B), Tlen=8 ⇒ tag 8 B
  {
    name: 'AES-CCM SP 800-38C C.2',
    cipher: 'aes-128-ccm',
    key: '404142434445464748494a4b4c4d4e4f',
    iv: '1011121314151617',
    aad: '000102030405060708090a0b0c0d0e0f',
    plaintext: '202122232425262728292a2b2c2d2e2f',
    ciphertext: 'd2a1f0e051ea5f62081a7792073d593d',
    tag: '1fc64fbfaccd',
    authTagLength: 6,
  },
  // C.3: N=12 B, A=20 B, P=24 B, Tlen=8 ⇒ tag 8 B
  {
    name: 'AES-CCM SP 800-38C C.3',
    cipher: 'aes-128-ccm',
    key: '404142434445464748494a4b4c4d4e4f',
    iv: '101112131415161718191a1b',
    aad: '000102030405060708090a0b0c0d0e0f10111213',
    plaintext: '202122232425262728292a2b2c2d2e2f3031323334353637',
    ciphertext: 'e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5',
    tag: '484392fbc1b09951',
    authTagLength: 8,
  },
  // --- AES-OCB, RFC 7253 §A — K = 000102...0F (16 B) ---
  // A.0: empty plaintext, empty AAD ⇒ ciphertext is just the 16-byte tag
  {
    name: 'AES-OCB RFC 7253 §A empty',
    cipher: 'aes-128-ocb',
    key: '000102030405060708090a0b0c0d0e0f',
    iv: 'bbaa99887766554433221100',
    aad: '',
    plaintext: '',
    ciphertext: '',
    tag: '785407bfffc8ad9edcc5520ac9111ee6',
  },
  // §A second vector (N=...221101): 8-byte plaintext, 8-byte AAD, 16-byte tag
  {
    name: 'AES-OCB RFC 7253 §A 8B P + 8B AAD',
    cipher: 'aes-128-ocb',
    key: '000102030405060708090a0b0c0d0e0f',
    iv: 'bbaa99887766554433221101',
    aad: '0001020304050607',
    plaintext: '0001020304050607',
    ciphertext: '6820b3657b6f615a',
    tag: '5725bda0d3b4eb3a257c9af1f8f03009',
  },
];

for (const kat of AEAD_KATS) {
  test(SUITE, `${kat.name} encrypt`, () => {
    const tagLen = kat.authTagLength ?? kat.tag.length / 2;
    const cipher = createCipheriv(
      kat.cipher,
      Buffer.from(kat.key, 'hex'),
      Buffer.from(kat.iv, 'hex'),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      { authTagLength: tagLen } as any,
    );
    if (kat.aad.length > 0) {
      const aadBuf = Buffer.from(kat.aad, 'hex');
      if (kat.cipher.includes('ccm')) {
        cipher.setAAD(aadBuf, { plaintextLength: kat.plaintext.length / 2 });
      } else {
        cipher.setAAD(aadBuf);
      }
    }
    const enc1 = cipher.update(Buffer.from(kat.plaintext, 'hex')) as Buffer;
    const enc2 = cipher.final() as Buffer;
    const ct = Buffer.concat([enc1, enc2]).toString('hex');
    const tag = cipher.getAuthTag().toString('hex');
    expect(ct).to.equal(kat.ciphertext);
    expect(tag).to.equal(kat.tag);
  });

  test(SUITE, `${kat.name} decrypt`, () => {
    const tagLen = kat.authTagLength ?? kat.tag.length / 2;
    const decipher = createDecipheriv(
      kat.cipher,
      Buffer.from(kat.key, 'hex'),
      Buffer.from(kat.iv, 'hex'),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      { authTagLength: tagLen } as any,
    );
    if (kat.aad.length > 0) {
      const aadBuf = Buffer.from(kat.aad, 'hex');
      if (kat.cipher.includes('ccm')) {
        decipher.setAAD(aadBuf, { plaintextLength: kat.plaintext.length / 2 });
      } else {
        decipher.setAAD(aadBuf);
      }
    }
    decipher.setAuthTag(Buffer.from(kat.tag, 'hex'));
    const dec1 = decipher.update(Buffer.from(kat.ciphertext, 'hex')) as Buffer;
    const dec2 = decipher.final() as Buffer;
    expect(Buffer.concat([dec1, dec2]).toString('hex')).to.equal(kat.plaintext);
  });
}
