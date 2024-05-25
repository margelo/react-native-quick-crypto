import QuickCrypto from 'react-native-quick-crypto';

// TODO use jasmine and write proper unit tests

export const benchmarkAgainstOldCrypto = async () => {
  console.log('Starting benchmark...');

  // TODO: Benchmar here!

  // QuickCrypto.runAsync().then((num: number) => {
  //   console.log('num', num);
  // });

  const hmac = QuickCrypto.createHmac('sha256', 'a secret');

  hmac.update('some data to hash');
  console.log(hmac.digest('hex'));

  // const key = await QuickCrypto.pbkdf2('secret', 'salt', 100000, 64, 'sha512');

  // const key2 = QuickCrypto.pbkdf2Sync('secret', 'salt', 100000, 64, 'sha512');

  // console.log('key1', key); // '3745e48...aa39b34'
  // console.log('key2', key2); // '3745e48...aa39b34'

  // console.log(`Benchmarks finished.`);
};
