import rnqc from 'react-native-quick-crypto';
import { p256 } from '@noble/curves/p256';
import type { BenchFn } from '../../types/benchmarks';
import { Bench } from 'tinybench';

const TIME_MS = 1000;

const ecdh_p256_genKeys: BenchFn = () => {
  const bench = new Bench({
    name: 'ECDH P-256 KeyGen',
    time: TIME_MS,
  });

  bench
    .add('rnqc', () => {
      const ecdh = rnqc.createECDH('prime256v1');
      ecdh.generateKeys();
    })
    .add('@noble/curves', () => {
      p256.utils.randomPrivateKey();
    });

  bench.warmupTime = 100;
  return bench;
};

const ecdh_p256_computeSecret: BenchFn = () => {
  const bench = new Bench({
    name: 'ECDH P-256 Compute',
    time: TIME_MS,
  });

  const alice = rnqc.createECDH('prime256v1');
  alice.generateKeys();
  const bob = rnqc.createECDH('prime256v1');
  bob.generateKeys();
  const bobPub = bob.getPublicKey();

  const nobleAlicePriv = p256.utils.randomPrivateKey();
  const nobleBobPriv = p256.utils.randomPrivateKey();
  const nobleBobPub = p256.getPublicKey(nobleBobPriv);

  bench
    .add('rnqc', () => {
      alice.computeSecret(bobPub);
    })
    .add('@noble/curves', () => {
      p256.getSharedSecret(nobleAlicePriv, nobleBobPub);
    });

  bench.warmupTime = 100;
  return bench;
};

export default [ecdh_p256_genKeys, ecdh_p256_computeSecret];
