import { describe, it } from '../../MochaRNAdapter';
import { expect } from 'chai';
import { QuickCrypto } from 'react-native-quick-crypto';
import { Buffer } from '@craftzdog/react-native-buffer';
import type { Done } from 'mocha';
import { fixtures } from './fixtures';
import type { HashAlgorithm } from '../../../../../src/keys';

type TestFixture = [string, string, number, number, string];

function ab2str(buf: ArrayBuffer) {
  return Buffer.from(buf).toString('hex');
}

// Copied from https://github.com/crypto-browserify/pbkdf2/blob/master/test/index.js
// SHA-1 vectors generated by Node.js
// SHA-256/SHA-512 test vectors from:
// https://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors
// https://stackoverflow.com/questions/15593184/pbkdf2-hmac-sha-512-test-vectors

describe('pbkdf2', () => {
  // RFC 6070 tests from Node.js
  {
    const test = (
      pass: string,
      salt: string,
      iterations: number,
      hash: string,
      length: number,
      expected: string,
      done: Done
    ) => {
      QuickCrypto.pbkdf2(
        pass,
        salt,
        iterations,
        length,
        hash as HashAlgorithm,
        function (err, result) {
          try {
            expect(err).to.eql(null);
            expect(result).to.not.eql(null);
            expect(ab2str(result as ArrayBuffer)).to.equal(expected);
            done();
          } catch (e) {
            done(e);
          }
        }
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
      it(`RFC 6070 - ${pass} ${salt} ${iterations} ${hash} ${length}`, (done: Done) => {
        test(pass, salt, iterations, hash, length, expected, done);
      });
    });
  }

  // eslint-disable-next-line @typescript-eslint/no-shadow
  var Buffer = require('safe-buffer').Buffer;

  it(' defaults to sha1 and handles buffers', (done: Done) => {
    var resultSync = QuickCrypto.pbkdf2Sync('password', 'salt', 1, 32);
    expect(ab2str(resultSync)).to.eql(
      '0c60c80f961f0e71f3a9b524af6012062fe037a6e0f0eb94fe8fc46bdc637164'
    );

    QuickCrypto.pbkdf2(
      Buffer.from('password'),
      Buffer.from('salt'),
      1,
      32,

      function (_, result) {
        // @ts-expect-error
        expect(ab2str(result)).to.eql(
          '0c60c80f961f0e71f3a9b524af6012062fe037a6e0f0eb94fe8fc46bdc637164'
        );
        done();
      }
    );
  });

  it('should throw if no callback is provided', function () {
    // @ts-expect-error
    expect(QuickCrypto.pbkdf2('password', 'salt', 1, 32, 'sha1')).to.throw(
      /No callback provided to pbkdf2/
    );
  });

  it('should throw if the password is not a string or an ArrayBuffer', function () {
    // @ts-expect-error
    expect(QuickCrypto.pbkdf2(['a'], 'salt', 1, 32, 'sha1')).to.throw(
      /Password must be a string, a Buffer, a typed array or a DataView/
    );
  });

  it(' should throw if the salt is not a string or an ArrayBuffer', function () {
    // @ts-expect-error
    expect(QuickCrypto.pbkdf2('a', ['salt'], 1, 32, 'sha1')).to.throw(
      /Salt must be a string, a Buffer, a typed array or a DataView/
    );
  });

  let algos = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'ripemd160'];
  algos.forEach(function (algorithm) {
    fixtures.valid.forEach(function (f: any) {
      let key: any, keyType: any, salt: any, saltType: any;
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
        key = f.key;
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
        salt = f.salt;
        saltType = 'string';
      }
      var expected = f.results[algorithm];
      var description =
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

      it(' async w/ ' + description, (done: Done) => {
        QuickCrypto.pbkdf2(
          key,
          salt,
          f.iterations,
          f.dkLen,
          algorithm as HashAlgorithm,
          function (err, result) {
            try {
              expect(err).to.eql(null);
              expect(result).to.not.eql(null);
              expect(ab2str(result as ArrayBuffer)).to.equal(expected);
              done();
            } catch (e) {
              done(e);
            }
          }
        );
      });

      it('sync w/ ' + description, function () {
        var result = QuickCrypto.pbkdf2Sync(
          key,
          salt,
          f.iterations,
          f.dkLen,
          algorithm as HashAlgorithm
        );
        expect(ab2str(result)).to.equal(expected);
      });
    });

    /*fixtures.invalid.forEach(function (f) {
      var description = algorithm + ' should throw ' + f.exception;

      it(' async w/ ' + description, function () {
        function noop() {}
        expect(
          crypto.pbkdf2(
            f.key,
            f.salt,
            f.iterations,
            f.dkLen,
            f.algo,
            noop
          )
        )
        .to.throw(new RegExp(f.exception));
      });

      it(' sync w/' + description, function () {
        expect(
          crypto.pbkdf2Sync(
            f.key,
            f.salt,
            f.iterations,
            f.dkLen,
            f.algo
          )
        )
        .to.throw(new RegExp(f.exception));
      });
    }); */
  });
});
