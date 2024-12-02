import { Bench } from 'tinybench';
import rnqc from 'react-native-quick-crypto';
import { ed25519 as noble } from '@noble/curves/ed25519';
import type { BenchFn } from '../../types/benchmarks';

const TIME_MS = 1000;

const ed25519_sign_verify_async: BenchFn = async () => {
  const message = 'hello world';
  const buffer = Buffer.from(message);
  const ab = buffer.buffer;
  const arr = new Uint8Array(buffer);

  // rnqc setup
  const ed = new rnqc.Ed('ed25519', {});
  await ed.generateKeyPair();

  // noble setup
  const noblePrivateKey = noble.utils.randomPrivateKey();
  const noblePublicKey = noble.getPublicKey(noblePrivateKey);

  const bench = new Bench({
    name: 'ed25519 sign/verify (async)',
    time: TIME_MS,
  });

  bench.add('rnqc', async () => {
    const signature = await ed.sign(ab);
    const verified = await ed.verify(signature, ab);
    if (!verified) {
      throw new Error('Signature verification failed');
    }
  });

  bench.add('@noble/curves/ed25519', () => {
    const signature = noble.sign(arr, noblePrivateKey);
    const verified = noble.verify(signature, arr, noblePublicKey);
    if (!verified) {
      throw new Error('Signature verification failed');
    }
  });

  bench.warmupTime = 100;
  return bench;
};

const ed25519_sign_verify_sync: BenchFn = () => {
  const message = 'hello world';
  const buffer = Buffer.from(message);
  const ab = buffer.buffer;
  const arr = new Uint8Array(buffer);

  // rnqc setup
  const ed = new rnqc.Ed('ed25519', {});
  ed.generateKeyPairSync();

  // noble setup
  const noblePrivateKey = noble.utils.randomPrivateKey();
  const noblePublicKey = noble.getPublicKey(noblePrivateKey);

  const bench = new Bench({
    name: 'ed25519 sign/verify (sync)',
    time: TIME_MS,
  });

  bench.add('rnqc', () => {
    const signature = ed.signSync(ab);
    const verified = ed.verifySync(signature, ab);
    if (!verified) {
      throw new Error('Signature verification failed');
    }
  });

  bench.add('@noble/curves/ed25519', () => {
    const signature = noble.sign(arr, noblePrivateKey);
    const verified = noble.verify(signature, arr, noblePublicKey);
    if (!verified) {
      throw new Error('Signature verification failed');
    }
  });

  bench.warmupTime = 100;
  return bench;
};

export default [ed25519_sign_verify_async, ed25519_sign_verify_sync];
