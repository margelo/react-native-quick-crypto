import rnqc from 'react-native-quick-crypto';
// @ts-expect-error crypto-browserify missing types
import browserify from 'crypto-browserify';
import type { BenchFn } from '../../types/benchmarks';
import { Bench } from 'tinybench';

const dh_modp14_genKeys: BenchFn = () => {
  const bench = new Bench({
    name: 'DH modp14 KeyGen',
    time: 200,
    iterations: 10, // Cap iterations for slow JS implementations
  });

  bench
    .add('rnqc', () => {
      const dh = rnqc.getDiffieHellman('modp14');
      dh.generateKeys();
    })
    .add('browserify', () => {
      const dh = browserify.getDiffieHellman('modp14');
      dh.generateKeys();
    });

  bench.warmupTime = 100;
  return bench;
};

const dh_modp14_computeSecret: BenchFn = () => {
  const bench = new Bench({
    name: 'DH modp14 Compute',
    time: 200,
    iterations: 10,
  });

  const alice = rnqc.getDiffieHellman('modp14');
  alice.generateKeys();
  const bob = rnqc.getDiffieHellman('modp14');
  bob.generateKeys();
  const bobPub = bob.getPublicKey();

  const bAlice = browserify.getDiffieHellman('modp14');
  bAlice.generateKeys();
  const bBob = browserify.getDiffieHellman('modp14');
  bBob.generateKeys();
  const bBobPub = bBob.getPublicKey();

  bench
    .add('rnqc', () => {
      alice.computeSecret(bobPub);
    })
    .add('browserify', () => {
      bAlice.computeSecret(bBobPub);
    });

  bench.warmupTime = 100;
  return bench;
};

export default [dh_modp14_genKeys, dh_modp14_computeSecret];
