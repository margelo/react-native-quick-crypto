import rnqc, { Buffer } from 'react-native-quick-crypto';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import type { BenchFn } from '../../types/benchmarks';
import { Bench } from 'tinybench';

const TIME_MS = 1000;

const ikm = new Uint8Array(32).fill(1);
const salt = new Uint8Array(32).fill(2);
const info = new Uint8Array(32).fill(3);
const length = 32;

const hkdf_sha256_async: BenchFn = () => {
  const bench = new Bench({
    name: 'hkdf sha256 32b (async)',
    time: TIME_MS,
  });

  const ikmBuf = Buffer.from(ikm);
  const saltBuf = Buffer.from(salt);
  const infoBuf = Buffer.from(info);

  bench
    .add('rnqc', () => {
      rnqc.hkdf('sha256', ikmBuf, saltBuf, infoBuf, length, () => {});
    })
    .add('@noble/hashes/hkdf', () => {
      hkdf(sha256, ikm, salt, info, length);
    });

  bench.warmupTime = 100;
  return bench;
};

const hkdf_sha256_sync: BenchFn = () => {
  const bench = new Bench({
    name: 'hkdf sha256 32b (sync)',
    time: TIME_MS,
  });

  const ikmBuf = Buffer.from(ikm);
  const saltBuf = Buffer.from(salt);
  const infoBuf = Buffer.from(info);

  bench
    .add('rnqc', () => {
      rnqc.hkdfSync('sha256', ikmBuf, saltBuf, infoBuf, length);
    })
    .add('@noble/hashes/hkdf', () => {
      hkdf(sha256, ikm, salt, info, length);
    });

  bench.warmupTime = 100;
  return bench;
};

export default [hkdf_sha256_async, hkdf_sha256_sync];
