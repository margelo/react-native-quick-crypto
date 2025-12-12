import rnqc from 'react-native-quick-crypto';
import * as noble from '@noble/hashes/scrypt';
import type { BenchFn } from '../../types/benchmarks';
import { Bench } from 'tinybench';

const TIME_MS = 1000;

// N=256, r=8, p=1 is light and fast enough for mobile benchmarking
// Higher values like 1024 can cause timeouts on slower devices
const N = 256;
const r = 8;
const p = 1;
const keylen = 64;

const scrypt_async: BenchFn = () => {
  const bench = new Bench({
    name: `scrypt N=${N} r=${r} p=${p} (async)`,
    time: TIME_MS,
  });

  bench
    .add('rnqc', async () => {
      try {
        await new Promise<void>((resolve, reject) => {
          rnqc.scrypt(
            'password',
            'salt',
            keylen,
            { N, r, p, maxmem: 32 * 1024 * 1024 },
            (err: unknown) => {
              if (err) reject(err);
              else resolve();
            },
          );
        });
      } catch (error) {
        console.error('RNQC scrypt error:', error);
        throw error;
      }
    })
    .add('@noble/hashes/scrypt', async () => {
      await noble.scryptAsync('password', 'salt', { N, r, p, dkLen: keylen });
    });

  bench.warmupTime = 100;
  return bench;
};

const scrypt_sync: BenchFn = () => {
  const bench = new Bench({
    name: `scrypt N=${N} r=${r} p=${p} (sync)`,
    time: TIME_MS,
  });

  bench
    .add('rnqc', () => {
      try {
        rnqc.scryptSync('password', 'salt', keylen, {
          N,
          r,
          p,
          maxmem: 32 * 1024 * 1024,
        });
      } catch (error) {
        console.error('RNQC scryptSync error:', error);
        throw error;
      }
    })
    .add('@noble/hashes/scrypt', () => {
      noble.scrypt('password', 'salt', { N, r, p, dkLen: keylen });
    });

  bench.warmupTime = 100;
  return bench;
};

export default [scrypt_async, scrypt_sync];
