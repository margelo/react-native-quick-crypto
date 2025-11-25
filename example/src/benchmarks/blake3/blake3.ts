import rnqc from 'react-native-quick-crypto';
import { blake3 as nobleBlake3 } from '@noble/hashes/blake3';
import type { BenchFn } from '../../types/benchmarks';
import { Bench } from 'tinybench';

const TIME_MS = 1000;

const blake3_32b: BenchFn = () => {
  const data = rnqc.randomBytes(32);

  const bench = new Bench({
    name: 'blake3 32b input',
    time: TIME_MS,
  });

  bench
    .add('rnqc', () => {
      rnqc.blake3(data);
    })
    .add('@noble/hashes/blake3', () => {
      nobleBlake3(data);
    });

  bench.warmupTime = 100;
  return bench;
};

const blake3_1kb: BenchFn = () => {
  const data = rnqc.randomBytes(1024);

  const bench = new Bench({
    name: 'blake3 1KB input',
    time: TIME_MS,
  });

  bench
    .add('rnqc', () => {
      rnqc.blake3(data);
    })
    .add('@noble/hashes/blake3', () => {
      nobleBlake3(data);
    });

  bench.warmupTime = 100;
  return bench;
};

const blake3_64kb: BenchFn = () => {
  const data = rnqc.randomBytes(64 * 1024);

  const bench = new Bench({
    name: 'blake3 64KB input',
    time: TIME_MS,
  });

  bench
    .add('rnqc', () => {
      rnqc.blake3(data);
    })
    .add('@noble/hashes/blake3', () => {
      nobleBlake3(data);
    });

  bench.warmupTime = 100;
  return bench;
};

const blake3_xof_256b: BenchFn = () => {
  const data = rnqc.randomBytes(32);

  const bench = new Bench({
    name: 'blake3 XOF 256b output',
    time: TIME_MS,
  });

  bench
    .add('rnqc', () => {
      rnqc.blake3(data, { dkLen: 256 });
    })
    .add('@noble/hashes/blake3', () => {
      nobleBlake3(data, { dkLen: 256 });
    });

  bench.warmupTime = 100;
  return bench;
};

const blake3_keyed: BenchFn = () => {
  const data = rnqc.randomBytes(64);
  const key = rnqc.randomBytes(32);

  const bench = new Bench({
    name: 'blake3 keyed MAC',
    time: TIME_MS,
  });

  bench
    .add('rnqc', () => {
      rnqc.blake3(data, { key });
    })
    .add('@noble/hashes/blake3', () => {
      nobleBlake3(data, { key });
    });

  bench.warmupTime = 100;
  return bench;
};

const blake3_streaming: BenchFn = () => {
  const chunk1 = rnqc.randomBytes(512);
  const chunk2 = rnqc.randomBytes(512);

  const bench = new Bench({
    name: 'blake3 streaming (2x 512b)',
    time: TIME_MS,
  });

  bench
    .add('rnqc', () => {
      const h = rnqc.createBlake3();
      h.update(chunk1);
      h.update(chunk2);
      h.digest();
    })
    .add('@noble/hashes/blake3', () => {
      const h = nobleBlake3.create({});
      h.update(chunk1);
      h.update(chunk2);
      h.digest();
    });

  bench.warmupTime = 100;
  return bench;
};

export default [
  blake3_32b,
  blake3_1kb,
  blake3_64kb,
  blake3_xof_256b,
  blake3_keyed,
  blake3_streaming,
];
