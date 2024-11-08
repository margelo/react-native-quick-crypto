/* eslint-disable @typescript-eslint/no-unused-expressions */
import { Buffer } from 'safe-buffer';
import { expect } from 'chai';
import { test } from '../util';
import { fixtures, type Fixture } from './fixtures';

import crypto, { ab2str } from 'react-native-quick-crypto';
import type { BinaryLike, HashAlgorithm } from 'react-native-quick-crypto';

type TestFixture = [string, string, number, number, string];

// Copied from https://github.com/crypto-browserify/pbkdf2/blob/master/test/index.js
// SHA-1 vectors generated by Node.js
// SHA-256/SHA-512 test vectors from:
// https://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors
// https://stackoverflow.com/questions/15593184/pbkdf2-hmac-sha-512-test-vectors

const SUITE = 'pbkdf2';

// RFC 6070 tests from Node.js
{
  const testFn = (
    pass: string,
    salt: string,
    iterations: number,
    hash: string,
    length: number,
    expected: string
  ) => {
    crypto.pbkdf2(
      pass,
      salt,
      iterations,
      length,
      hash as HashAlgorithm,
      function (err, result) {
        expect(err).to.be.null;
        expect(result).not.to.be.null;
        expect(ab2str(result as ArrayBuffer)).to.equal(expected);
      },
    );
  };

  const kTests: TestFixture[] = [
    ['password', 'salt', 1, 20, '120fb6cffcf8b32c43e7225256c4f837a86548c9'],
    ['password', 'salt', 2, 20, 'ae4d0c95af6b46d32d0adff928f06dd02a303f8e'],
    [
      'password',
      'salt',
      4096,
      20,
      'c5e478d59288c841aa530db6845c4c8d962893a0',
    ],
    [
      'passwordPASSWORDpassword',
      'saltSALTsaltSALTsaltSALTsaltSALTsalt',
      4096,
      25,
      '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c',
    ],
    ['pass\0word', 'sa\0lt', 4096, 16, '89b69d0516f829893c696226650a8687'],
    [
      'password',
      'salt',
      32,
      32,
      '64c486c55d30d4c5a079b8823b7d7cb37ff0556f537da8410233bcec330ed956',
    ],
  ];

  kTests.forEach(([pass, salt, iterations, length, expected]) => {
    const hash = 'sha256';
    test(SUITE, `RFC 6070 - ${pass} ${salt} ${iterations} ${hash} ${length}`, () => {
      testFn(pass, salt, iterations, hash, length, expected);
    });
  });
}

test(SUITE, 'handles buffers', () => {
  const resultSync = crypto.pbkdf2Sync('password', 'salt', 1, 32);
  expect(ab2str(resultSync)).to.equal(
    '0c60c80f961f0e71f3a9b524af6012062fe037a6e0f0eb94fe8fc46bdc637164',
  );

  crypto.pbkdf2(
    Buffer.from('password'),
    Buffer.from('salt'),
    1,
    32,
    'sha1',
    function (_, result) {
      expect(result?.toString()).to.equal(
        '0c60c80f961f0e71f3a9b524af6012062fe037a6e0f0eb94fe8fc46bdc637164',
      );
    },
  );
});

test(SUITE, 'should throw if no callback is provided', function () {
  expect(() => {
    // @ts-expect-error - testing no callback
    crypto.pbkdf2('password', 'salt', 1, 32, 'sha1');
  }).to.throw(
    /No callback provided to pbkdf2/,
  );
});

test(SUITE, 'should throw if the password is not a string or an ArrayBuffer', function () {
  expect(() => {
    // @ts-expect-error - testing bad password
    crypto.pbkdf2(['a'], 'salt', 1, 32, 'sha1');
  }).to.throw(
    /No callback provided to pbkdf2/,
  );
});

test(SUITE, ' should throw if the salt is not a string or an ArrayBuffer', function () {
  expect(() => {
    // @ts-expect-error - testing bad salt
    crypto.pbkdf2('a', ['salt'], 1, 32, 'sha1');
  }).to.throw(
    /No callback provided to pbkdf2/,
  );
});

const algos = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'ripemd160'];
algos.forEach(function (algorithm) {
  fixtures.valid.forEach(function (f: Fixture) {
    // TODO: check these types once nitro port is done
    let key: BinaryLike,
      keyType: string,
      salt: BinaryLike,
      saltType: string;
    if (f.keyUint8Array) {
      key = new Uint8Array(f.keyUint8Array);
      keyType = 'Uint8Array';
    } else if (f.keyInt32Array) {
      key = new Int32Array(f.keyInt32Array);
      keyType = 'Int32Array';
    } else if (f.keyFloat64Array) {
      key = new Float64Array(f.keyFloat64Array);
      keyType = 'Float64Array';
    } else if (f.keyHex) {
      key = Buffer.from(f.keyHex, 'hex');
      keyType = 'hex';
    } else {
      key = f.key as BinaryLike;
      keyType = 'string';
    }
    if (f.saltUint8Array) {
      salt = new Uint8Array(f.saltUint8Array);
      saltType = 'Uint8Array';
    } else if (f.saltInt32Array) {
      salt = new Int32Array(f.saltInt32Array);
      saltType = 'Int32Array';
    } else if (f.saltFloat64Array) {
      salt = new Float64Array(f.saltFloat64Array);
      saltType = 'Float64Array';
    } else if (f.saltHex) {
      salt = Buffer.from(f.saltHex, 'hex');
      saltType = 'hex';
    } else {
      salt = f.salt as BinaryLike;
      saltType = 'string';
    }
    const expected = f.results ? f.results[algorithm] : undefined;
    const description =
      algorithm +
      ' encodes "' +
      key +
      '" (' +
      keyType +
      ') with salt "' +
      salt +
      '" (' +
      saltType +
      ') with ' +
      algorithm +
      ' to ' +
      expected;

    test(SUITE, ' async w/ ' + description, () => {
      crypto.pbkdf2(
        key,
        salt,
        f.iterations as number,
        f.dkLen as number,
        algorithm as HashAlgorithm,
        function (err, result) {
          expect(err).to.be.null;
          expect(result).not.to.be.null;
          expect(ab2str(result as ArrayBuffer)).to.equal(expected);
        },
      );
    });

    test(SUITE, 'sync w/ ' + description, function () {
      const result = crypto.pbkdf2Sync(
        key,
        salt,
        f.iterations as number,
        f.dkLen as number,
        algorithm as HashAlgorithm,
      );
      expect(ab2str(result)).to.equal(expected);
    });
  });

  // // TODO: fix the 'invalid' tests
  // fixtures.invalid.forEach(function (f: Fixture) {
  //   const description = algorithm + ' should throw ' + f.exception;

  //   test(SUITE, ' async w/ ' + description, function () {
  //     function noop() {}
  //     expect(() => {
  //       crypto.pbkdf2(
  //         f.key as BinaryLike,
  //         f.salt as BinaryLike,
  //         f.iterations as number,
  //         f.dkLen as number,
  //         algorithm as HashAlgorithm,
  //         noop
  //       )
  //     }).to.throw(f.exception);
  //   });

  //   test(SUITE, ' sync w/' + description, function () {
  //     expect(() => {
  //       crypto.pbkdf2Sync(
  //         f.key as BinaryLike,
  //         f.salt as BinaryLike,
  //         f.iterations as number,
  //         f.dkLen as number,
  //         algorithm as HashAlgorithm,
  //       )
  //     }).to.throw(f.exception);
  //   });
  // });

});