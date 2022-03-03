import { describe, it } from '../MochaRNAdapter';
import chai from 'chai';
import { FastCrypto } from 'react-native-fast-crypto';
import { Buffer } from '@craftzdog/react-native-buffer';

function ab2str(buf: ArrayBuffer) {
  return Buffer.from(buf).toString('hex');
}

export const pbkdf2RegisterTests = () => {
  // Copied from https://github.com/crypto-browserify/pbkdf2/blob/master/test/index.js
  // SHA-1 vectors generated by Node.js
  // SHA-256/SHA-512 test vectors from:
  // https://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors
  // https://stackoverflow.com/questions/15593184/pbkdf2-hmac-sha-512-test-vectors
  var { fixtures } = require('./fixtures');
  var Buffer = require('safe-buffer').Buffer;

  fixtures.invalid.push(
    {
      key: 'password',
      salt: 'salt',
      iterations: 1,
      dkLen: -1,
      exception: 'Bad key length',
    },
    {
      key: 'password',
      salt: 'salt',
      iterations: 1,
      dkLen: 4073741824,
      exception: 'Bad key length',
    }
  );

  fixtures.invalid.push(
    {
      key: 'password',
      salt: 'salt',
      iterations: 1,
      dkLen: NaN,
      exception: 'Bad key length',
    },
    {
      key: 'password',
      salt: 'salt',
      iterations: 1,
      dkLen: Infinity,
      exception: 'Bad key length',
    }
  );

  fixtures.valid.push({
    description: 'Unicode salt, no truncation',
    key: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    salt: 'mnemonicメートルガバヴァぱばぐゞちぢ十人十色',
    iterations: 2048,
    dkLen: 64,
    results: {
      sha1: '7e042a2f41ba17e2235fbc794e22a150816b0f54a1dfe113919fccb7a056066a109385e538f183c92bad896ae8b7d8e0f4cd66df359c77c8c7785cd1001c9a2c',
      sha256:
        '0b57118f2b6b079d9371c94da3a8315c3ada87a1e819b40c4c4e90b36ff2d3c8fd7555538b5119ac4d3da7844aa4259d92f9dd2188e78ac33c4b08d8e6b5964b',
      sha512:
        'ba553eedefe76e67e2602dc20184c564010859faada929a090dd2c57aacb204ceefd15404ab50ef3e8dbeae5195aeae64b0def4d2eead1cdc728a33ced520ffd',
      sha224:
        'd76474c525616ce2a527d23df8d6f6fcc4251cc3535cae4e955810a51ead1ec6acbe9c9619187ca5a3c4fd636de5b5fe58d031714731290bbc081dbf0fcb8fc1',
      sha384:
        '15010450f456769467e834db7fa93dd9d353e8bb733b63b0621090f96599ac3316908eb64ac9366094f0787cd4bfb2fea25be41dc271a19309710db6144f9b34',
      ripemd160:
        '255321c22a32f41ed925032043e01afe9cacf05470c6506621782c9d768df03c74cb3fe14a4296feba4c2825e736486fb3871e948f9c413ca006cc20b7ff6d37',
    },
  });

  fixtures.valid.push({
    description: 'Unicode salt, suffers from truncation',
    key: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    salt: 'mnemonicメートルガバヴァぱばぐゞちぢ十人十色',
    iterations: 2048,
    dkLen: 64,
    results: {
      sha1: 'd85d14adcb7bdb5d976160e504f520a98cf71aca4cd5fceadf37759743bd6e1d2ff78bdd4403552aef7658094384b341ede80fffd334182be076f9d988a0a40f',
      sha256:
        'b86b5b900c29ed2724359afd793e10ffc1eb0e7d6f624fc9c85b8ac1785d9a2f0575af52a2338e611f2e6cffdee544adfff6f3d4f43be2ba0e2bd7e917b38a14',
      sha512:
        '3a863fa00f2e97a83fa9b18805e0047a6282cbae0ff48438b33a14475771c52d05137daa12e364cb34d84547ac07568b801c5c7f8dd4baaeee18a67a5c6a3377',
      sha224:
        '95727793842437774ad9ae27b8154a6f37f208b75a03d3a4d4a2443422bb6bc85efcfa92aa4376926ea89a8f5a63118eecdb58c8ca28ab31007da79437e0a1ef',
      sha384:
        '1a7e02e8ba0e357269a55642024b85738b95238d6cdc49bc440204995aefeff499e22cba76d4c7e96b7d4a9596a70e744f53fa94f3547e7dc506fcaf16ceb4a2',
      ripemd160:
        'bac7849db13e90604620945695288ffee20369107c3a6632d6b1d6b926175ac914319b5a742e6b1a37b82841b6f010ad47ebdb5cd608026eb48513bf68cb54f5',
    },
  });

  describe('pbkdf2 tests', () => {
    it(' defaults to sha1 and handles buffers', function () {
      var resultSync = FastCrypto.pbkdf2Sync('password', 'salt', 1, 32);
      chai
        .expect(ab2str(resultSync))
        .to.eql(
          '0c60c80f961f0e71f3a9b524af6012062fe037a6e0f0eb94fe8fc46bdc637164'
        );

      FastCrypto.pbkdf2(
        Buffer.from('password'),
        Buffer.from('salt'),
        1,
        32,
        function (err, result) {
          chai
            .expect(ab2str(result))
            .to.eql(
              '0c60c80f961f0e71f3a9b524af6012062fe037a6e0f0eb94fe8fc46bdc637164'
            );
        }
      );
    });

   /* it('should throw if no callback is provided', function () {
      chai
        .expect(FastCrypto.pbkdf2('password', 'salt', 1, 32, 'sha1'))
        .to.throw(/No callback provided to pbkdf2/);
    });

    it('should throw if the password is not a string or an ArrayBuffer', function () {
      chai
        .expect(FastCrypto.pbkdf2(['a'], 'salt', 1, 32, 'sha1'))
        .to.throw(
          /Password must be a string, a Buffer, a typed array or a DataView/
        );
    });

    it(' should throw if the salt is not a string or an ArrayBuffer', function () {
      chai
        .expect(FastCrypto.pbkdf2('a', ['salt'], 1, 32, 'sha1'))
        .to.throw(
          /Salt must be a string, a Buffer, a typed array or a DataView/
        );
    });*/

    /*var algos = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'ripemd160'];
    algos.forEach(function (algorithm) {
      fixtures.valid.forEach(function (f) {
        var key, keyType, salt, saltType;
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

        it(' async w/ ' + description, function () {
          FastCrypto.pbkdf2(
            key,
            salt,
            f.iterations,
            f.dkLen,
            algorithm,
            function (err, result) {
              chai.expect(result.toString('hex')).to.equal(expected);
            }
          );
        });

        it('sync w/ ' + description, function () {
          var result = FastCrypto.pbkdf2Sync(
            key,
            salt,
            f.iterations,
            f.dkLen,
            algorithm
          );
          chai.expect(result.toString('hex')).to.equal(expected);
        });
      });

    /*fixtures.invalid.forEach(function (f) {
        var description = algorithm + ' should throw ' + f.exception;

        it(' async w/ ' + description, function () {
          function noop() {}
          chai
            .expect(
              FastCrypto.pbkdf2(
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
          chai
            .expect(
              FastCrypto.pbkdf2Sync(
                f.key,
                f.salt,
                f.iterations,
                f.dkLen,
                f.algo
              )
            )
            .to.throw(new RegExp(f.exception));
        });
      }); 
    });*/
  });
};
