import { FastCrypto } from 'react-native-fast-crypto';

export const benchmarkAgainstOldCrypto = async () => {
  console.log('Starting benchmark...');

  // TODO: Benchmar here!

  FastCrypto.runAsync().then((num) => {
    console.log('num', num);
  });

  console.log(`Benchmarks finished.`);
};
