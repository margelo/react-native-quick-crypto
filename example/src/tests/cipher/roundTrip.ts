import {
  Buffer,
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
  const encrypted = Buffer.concat([encryptedPart1, encryptedPart2]);
  const tag = cipher.getAuthTag();

  // Decrypt
  const decipher: Decipher | null = createDecipheriv(cipherName, key, iv, {
    authTagLength: tagLength,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any);
  if (aad) {
    const options = isCCM ? { plaintextLength: plaintext.length } : undefined;
    decipher.setAAD(aad, options); // Pass plaintextLength for CCM
  }
  decipher.setAuthTag(tag);
  const decryptedPart1: Buffer = decipher.update(encrypted) as Buffer;
  const decryptedPart2: Buffer = decipher.final() as Buffer;
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
