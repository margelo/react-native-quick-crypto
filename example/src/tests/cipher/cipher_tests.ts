import { Buffer } from '@craftzdog/react-native-buffer';
import {
  getCiphers,
  createCipheriv,
  createDecipheriv,
  randomFillSync,
  xsalsa20,
  type Cipher,
  type Decipher,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';

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

// --- Helper Functions ---
// Helper for testing authenticated modes (GCM, CCM, OCB, Poly1305, SIV)
function roundTripAuth(
  cipherName: string,
  key: Buffer,
  iv: Buffer,
  plaintext: Buffer,
  aad?: Buffer,
  tagLength?: number, // Usually 16 for these modes
) {
  let tag: Buffer | null = null;
  const isChaChaPoly = cipherName.toLowerCase() === 'chacha20-poly1305'; // Exact match
  const isCCM = cipherName.includes('CCM');

  // Encrypt
  const cipher: Cipher | null = createCipheriv(cipherName, key, iv, {
    authTagLength: tagLength,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any);
  if (aad) {
    const options = isCCM ? { plaintextLength: plaintext.length } : undefined;
    cipher.setAAD(aad, options); // Pass plaintextLength for CCM
  }
  const encryptedPart1: Buffer = cipher.update(plaintext) as Buffer;
  const encryptedPart2: Buffer = cipher.final() as Buffer;
  let encrypted = Buffer.concat([encryptedPart1, encryptedPart2]);

  if (!isChaChaPoly) {
    // ChaChaPoly implicitly includes tag in final output
    tag = cipher.getAuthTag() as Buffer;
  } else {
    // For ChaChaPoly, extract tag from the end of ciphertext
    const expectedTagLength = tagLength ?? 16;
    tag = encrypted.subarray(encrypted.length - expectedTagLength);
    encrypted = encrypted.subarray(0, encrypted.length - expectedTagLength);
  }

  // Keep original encrypted buffer for ChaChaPoly decryption
  const originalEncryptedForChaCha = isChaChaPoly
    ? Buffer.concat([encryptedPart1, encryptedPart2])
    : null;

  // Decrypt
  const decipher: Decipher | null = createDecipheriv(cipherName, key, iv, {
    authTagLength: tagLength,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any);
  if (aad) {
    const options = isCCM ? { plaintextLength: plaintext.length } : undefined;
    decipher.setAAD(aad, options); // Pass plaintextLength for CCM
  }
  // Do not set AuthTag explicitly for ChaChaPoly
  if (!isChaChaPoly) {
    decipher.setAuthTag(tag);
  }

  // For ChaChaPoly, pass the original buffer with tag appended
  const bufferToDecrypt = isChaChaPoly
    ? originalEncryptedForChaCha!
    : encrypted;
  const decryptedPart1: Buffer = decipher.update(bufferToDecrypt) as Buffer;
  const decryptedPart2: Buffer = decipher.final() as Buffer; // Final verifies tag for ChaChaPoly
  const decrypted = Buffer.concat([decryptedPart1, decryptedPart2]);

  // Verify
  expect(decrypted).eql(plaintext);
}

// Helper for non-authenticated modes
function roundTrip(
  cipherName: string,
  key: Buffer | string,
  iv: Buffer | string,
  plaintext: Buffer,
) {
  // Encrypt
  const cipher: Cipher | null = createCipheriv(cipherName, key, iv);
  const encryptedPart1: Buffer = cipher.update(plaintext) as Buffer;
  const encryptedPart2: Buffer = cipher.final() as Buffer;
  const encrypted = Buffer.concat([encryptedPart1, encryptedPart2]);

  // Decrypt
  const decipher: Decipher | null = createDecipheriv(cipherName, key, iv);
  const decryptedPart1: Buffer = decipher.update(encrypted) as Buffer;
  const decryptedPart2: Buffer = decipher.final() as Buffer;
  const decrypted = Buffer.concat([decryptedPart1, decryptedPart2]);

  // Verify
  expect(decrypted).eql(plaintext); // Use Chai's eql for deep equality
}

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
  // roundtrip expects Buffers, convert strings first
  roundTrip(
    'aes-128-cbc',
    key16.toString('hex'),
    iv.toString('hex'),
    plaintextBuffer,
  );
});

test(SUITE, 'buffers', () => {
  roundTrip('aes-128-cbc', key16, iv, plaintextBuffer);
});

// loop through each cipher and test roundtrip
const allCiphers = getCiphers();
allCiphers.forEach(cipherName => {
  test(SUITE, cipherName, () => {
    try {
      // Determine correct key length
      let keyLen = 32; // Default to 256-bit
      if (cipherName.includes('128')) {
        keyLen = 16;
      } else if (cipherName.includes('192')) {
        keyLen = 24;
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

      // Select IV size based on mode
      const testIv: Uint8Array =
        cipherName.includes('GCM') ||
        cipherName.includes('OCB') ||
        cipherName.includes('CCM')
          ? iv12
          : iv16;

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
