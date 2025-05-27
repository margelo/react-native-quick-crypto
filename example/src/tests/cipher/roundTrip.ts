import { Buffer } from '@craftzdog/react-native-buffer';
import {
  createCipheriv,
  createDecipheriv,
  type Cipher,
  type Decipher,
} from 'react-native-quick-crypto';
import { expect } from 'chai';

// --- Helper Functions ---
// Helper for testing authenticated modes (GCM, CCM, OCB, Poly1305, SIV)
export function roundTripAuth(
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
    tag = cipher.getAuthTag();
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
export function roundTrip(
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
