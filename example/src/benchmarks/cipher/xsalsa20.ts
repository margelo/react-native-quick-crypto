import { Bench } from 'tinybench';
import rnqc from 'react-native-quick-crypto';
import { xsalsa20 as nobleXSalsa20 } from '@noble/ciphers/salsa.js';
import type { BenchFn } from '../../types/benchmarks';

const TIME_MS = 1000;

const xsalsa20_encrypt_decrypt: BenchFn = () => {
  // Create test data using randomBytes
  const key = rnqc.randomBytes(32); // 32 bytes key for XSalsa20
  const nonce = rnqc.randomBytes(24); // 24 bytes nonce for XSalsa20
  const data = rnqc.randomBytes(1024); // 1KB of data to encrypt

  const bench = new Bench({
    name: 'XSalsa20 encrypt/decrypt (1KB)',
    time: TIME_MS,
  });

  bench.add('rnqc', () => {
    // XSalsa20 is a stream cipher, so encryption and decryption are the same operation
    const encrypted = rnqc.xsalsa20(key, nonce, data);
    if (encrypted.length !== data.length) {
      throw new Error('Encryption failed: output size mismatch');
    }

    // Decrypt by applying XSalsa20 again
    const decrypted = rnqc.xsalsa20(key, nonce, encrypted);

    // Verify decryption worked correctly
    for (let i = 0; i < data.length; i++) {
      if (data[i] !== decrypted[i]) {
        throw new Error(`Decryption verification failed at index ${i}`);
      }
    }
  });

  bench.add('@noble/ciphers/salsa', () => {
    // Encrypt
    const encrypted = nobleXSalsa20(key, nonce, data);
    if (encrypted.length !== data.length) {
      throw new Error('Encryption failed: output size mismatch');
    }

    // Decrypt
    const decrypted = nobleXSalsa20(key, nonce, encrypted);

    // Verify
    for (let i = 0; i < data.length; i++) {
      if (data[i] !== decrypted[i]) {
        throw new Error(`Decryption verification failed at index ${i}`);
      }
    }
  });

  bench.warmupTime = 100;
  return bench;
};

const xsalsa20_encrypt_decrypt_large: BenchFn = () => {
  // Create test data using randomBytes
  const key = rnqc.randomBytes(32); // 32 bytes key for XSalsa20
  const nonce = rnqc.randomBytes(24); // 24 bytes nonce for XSalsa20
  // Create larger test data (64KB) using randomBytes
  const data = rnqc.randomBytes(64 * 1024);

  const bench = new Bench({
    name: 'XSalsa20 encrypt/decrypt (64KB)',
    time: TIME_MS,
  });

  bench.add('rnqc', () => {
    // Encrypt
    const encrypted = rnqc.xsalsa20(key, nonce, data);
    if (encrypted.length !== data.length) {
      throw new Error('Encryption failed: output size mismatch');
    }

    // Decrypt
    const decrypted = rnqc.xsalsa20(key, nonce, encrypted);

    // Verify (checking first and last 100 bytes for performance)
    for (let i = 0; i < 100; i++) {
      if (data[i] !== decrypted[i]) {
        throw new Error(`Decryption verification failed at start index ${i}`);
      }
    }

    for (let i = data.length - 100; i < data.length; i++) {
      if (data[i] !== decrypted[i]) {
        throw new Error(`Decryption verification failed at end index ${i}`);
      }
    }
  });

  bench.add('@noble/ciphers/salsa', () => {
    // Encrypt
    const encrypted = nobleXSalsa20(key, nonce, data);
    if (encrypted.length !== data.length) {
      throw new Error('Encryption failed: output size mismatch');
    }

    // Decrypt
    const decrypted = nobleXSalsa20(key, nonce, encrypted);

    // Verify (checking first and last 100 bytes for performance)
    for (let i = 0; i < 100; i++) {
      if (data[i] !== decrypted[i]) {
        throw new Error(`Decryption verification failed at start index ${i}`);
      }
    }

    for (let i = data.length - 100; i < data.length; i++) {
      if (data[i] !== decrypted[i]) {
        throw new Error(`Decryption verification failed at end index ${i}`);
      }
    }
  });

  bench.warmupTime = 100;
  return bench;
};

export default [xsalsa20_encrypt_decrypt, xsalsa20_encrypt_decrypt_large];
