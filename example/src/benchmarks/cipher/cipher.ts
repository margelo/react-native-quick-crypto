import rnqc from 'react-native-quick-crypto';
// @ts-expect-error - crypto-browserify is not typed
import browserify from 'crypto-browserify';
import { gcm } from '@noble/ciphers/aes.js';
import type { BenchFn } from '../../types/benchmarks';
import { Bench } from 'tinybench';
import { buffer1MB } from '../testData';

// Generate a key for AES-256-GCM
const key = rnqc.randomBytes(32);
const iv = rnqc.randomBytes(12);

// @noble requires Uint8Array
const nobleKey = new Uint8Array(key);
const nobleIv = new Uint8Array(iv);

const cipher_aes256gcm_1mb_buffer: BenchFn = () => {
  const bench = new Bench({
    name: 'cipher aes256gcm 1MB Buffer',
    iterations: 1,
    warmupIterations: 0,
  });

  const nobleData = new Uint8Array(buffer1MB);

  bench
    .add('rnqc', () => {
      const cipher = rnqc.createCipheriv('aes-256-gcm', key, iv);
      cipher.update(buffer1MB);
      cipher.final();
    })
    .add('@noble/ciphers/aes', () => {
      const cipher = gcm(nobleKey, nobleIv);
      cipher.encrypt(nobleData);
    })
    .add('browserify', () => {
      const cipher = browserify.createCipheriv('aes-256-gcm', key, iv);
      cipher.update(buffer1MB);
      cipher.final();
    });

  return bench;
};

export default [cipher_aes256gcm_1mb_buffer];
