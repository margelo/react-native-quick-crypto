import { expect } from 'chai';
// import type { Buffer } from '@craftzdog/react-native-buffer';
import { describe, it } from '../../MochaRNAdapter';
import crypto from 'react-native-quick-crypto';
import { assertThrowsAsync } from '../util';
import type {
  AESAlgorithm,
  AESLength,
  AnyAlgorithm,
  CryptoKey,
  CryptoKeyPair,
  KeyUsage,
  NamedCurve,
} from '../../../../../src/keys';
import { isCryptoKey } from '../../../../../src/keys';

const { subtle } = crypto;

const allUsages: KeyUsage[] = [
  'encrypt',
  'decrypt',
  'sign',
  'verify',
  'deriveBits',
  'deriveKey',
  'wrapKey',
  'unwrapKey',
];

type Vector = {
  algorithm?: object;
  result: string;
  usages: KeyUsage[];
};

type Vectors = {
  [key in string]: Vector;
};

const vectors: Vectors = {
  // 'AES-CTR': {
  //   algorithm: { length: 256 },
  //   result: 'CryptoKey',
  //   usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  // },
  // 'AES-CBC': {
  //   algorithm: { length: 256 },
  //   result: 'CryptoKey',
  //   usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  // },
  // 'AES-GCM': {
  //   algorithm: { length: 256 },
  //   result: 'CryptoKey',
  //   usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  // },
  // 'AES-KW': {
  //   algorithm: { length: 256 },
  //   result: 'CryptoKey',
  //   usages: ['wrapKey', 'unwrapKey'],
  // },
  // 'HMAC': {
  //   algorithm: { length: 256, hash: 'SHA-256' },
  //   result: 'CryptoKey',
  //   usages: ['sign', 'verify'],
  // },
  // 'RSASSA-PKCS1-v1_5': {
  //   algorithm: {
  //     modulusLength: 1024,
  //     publicExponent: new Uint8Array([1, 0, 1]),
  //     hash: 'SHA-256',
  //   },
  //   result: 'CryptoKeyPair',
  //   usages: ['sign', 'verify'],
  // },
  // 'RSA-PSS': {
  //   algorithm: {
  //     modulusLength: 1024,
  //     publicExponent: new Uint8Array([1, 0, 1]),
  //     hash: 'SHA-256',
  //   },
  //   result: 'CryptoKeyPair',
  //   usages: ['sign', 'verify'],
  // },
  // 'RSA-OAEP': {
  //   algorithm: {
  //     modulusLength: 1024,
  //     publicExponent: new Uint8Array([1, 0, 1]),
  //     hash: 'SHA-256',
  //   },
  //   result: 'CryptoKeyPair',
  //   usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  // },
  ECDSA: {
    algorithm: { namedCurve: 'P-521' },
    result: 'CryptoKeyPair',
    usages: ['sign', 'verify'],
  },
  ECDH: {
    algorithm: { namedCurve: 'P-521' },
    result: 'CryptoKeyPair',
    usages: ['deriveKey', 'deriveBits'],
  },
  // 'Ed25519': {
  //   result: 'CryptoKeyPair',
  //   usages: ['sign', 'verify'],
  // },
  // 'Ed448': {
  //   result: 'CryptoKeyPair',
  //   usages: ['sign', 'verify'],
  // },
  // 'X25519': {
  //   result: 'CryptoKeyPair',
  //   usages: ['deriveKey', 'deriveBits'],
  // },
  // 'X448': {
  //   result: 'CryptoKeyPair',
  //   usages: ['deriveKey', 'deriveBits'],
  // },
};

describe('subtle - generateKey', () => {
  // Test invalid algorithms
  {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async function testInvalidAlgorithm(algorithm: any) {
      // one test is slightly different than the others
      const errorText =
        algorithm.hash === 'SHA'
          ? 'Invalid Hash Algorithm'
          : 'Unrecognized algorithm name';
      const algo = JSON.stringify(algorithm);
      it(`invalid algo: ${algo}`, async () => {
        await assertThrowsAsync(
          async () =>
            // @ts-expect-error bad extractable
            // The extractable and usages values are invalid here also,
            // but the unrecognized algorithm name should be caught first.
            await subtle.generateKey(algorithm, 7, []),
          errorText,
        );
      });
    }

    const invalidAlgoTests = [
      'AES',
      { name: 'AES' },
      { name: 'AES-CMAC' },
      { name: 'AES-CFB' },
      { name: 'HMAC', hash: 'MD5' },
      {
        name: 'RSA',
        hash: 'SHA-256',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
      },
      {
        name: 'RSA-PSS',
        hash: 'SHA',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
      },
      {
        name: 'EC',
        namedCurve: 'P521',
      },
    ];

    invalidAlgoTests.map(testInvalidAlgorithm);
  }

  // Test bad usages
  {
    async function testBadUsage(name: string) {
      it(`bad usages: ${name}`, async () => {
        await assertThrowsAsync(
          async () =>
            await subtle.generateKey(
              {
                name: name as AnyAlgorithm,
                ...vectors[name]?.algorithm,
              },
              true,
              [],
            ),
          'Usages cannot be empty',
        );

        // For CryptoKeyPair results the private key
        // usages must not be empty.
        // - ECDH(-like) algorithm key pairs only have private key usages
        // - Signing algorithm key pairs may pass a non-empty array but
        //   with only a public key usage
        if (
          vectors[name]?.result === 'CryptoKeyPair' &&
          vectors[name]?.usages.includes('verify')
        ) {
          await assertThrowsAsync(
            async () =>
              await subtle.generateKey(
                {
                  name: name as AnyAlgorithm,
                  ...vectors[name]?.algorithm,
                },
                true,
                ['verify'],
              ),
            'Usages cannot be empty',
          );
        }

        const invalidUsages: KeyUsage[] = [];
        allUsages.forEach((usage) => {
          if (!vectors[name]?.usages.includes(usage)) {
            invalidUsages.push(usage);
          }
        });
        for (const invalidUsage of invalidUsages) {
          await assertThrowsAsync(
            async () =>
              await subtle.generateKey(
                {
                  name: name as AnyAlgorithm,
                  ...vectors[name]?.algorithm,
                },
                true,
                [...(vectors[name]?.usages as KeyUsage[]), invalidUsage],
              ),
            'Unsupported key usage',
          );
        }
      });
    }

    const badUsageTests = Object.keys(vectors);
    badUsageTests.map(testBadUsage);
  }

  /*
  // Test RSA key generation
  {
    async function test(
      name,
      modulusLength,
      publicExponent,
      hash,
      privateUsages,
      publicUsages = privateUsages
    ) {
      let usages = privateUsages;
      if (publicUsages !== privateUsages) usages = usages.concat(publicUsages);
      const { publicKey, privateKey } = await subtle.generateKey(
        {
          name,
          modulusLength,
          publicExponent,
          hash,
        },
        true,
        usages
      );

      assert(publicKey);
      assert(privateKey);
      assert(isCryptoKey(publicKey));
      assert(isCryptoKey(privateKey));

      assert(publicKey instanceof CryptoKey);
      assert(privateKey instanceof CryptoKey);

      assert.strictEqual(publicKey.type, 'public');
      assert.strictEqual(privateKey.type, 'private');
      assert.strictEqual(publicKey.toString(), '[object CryptoKey]');
      assert.strictEqual(privateKey.toString(), '[object CryptoKey]');
      assert.strictEqual(publicKey.extractable, true);
      assert.strictEqual(privateKey.extractable, true);
      assert.deepStrictEqual(publicKey.usages, publicUsages);
      assert.deepStrictEqual(privateKey.usages, privateUsages);
      assert.strictEqual(publicKey.algorithm.name, name);
      assert.strictEqual(publicKey.algorithm.modulusLength, modulusLength);
      assert.deepStrictEqual(publicKey.algorithm.publicExponent, publicExponent);
      assert.strictEqual(
        KeyObject.from(publicKey).asymmetricKeyDetails.publicExponent,
        bigIntArrayToUnsignedBigInt(publicExponent)
      );
      assert.strictEqual(publicKey.algorithm.hash.name, hash);
      assert.strictEqual(privateKey.algorithm.name, name);
      assert.strictEqual(privateKey.algorithm.modulusLength, modulusLength);
      assert.deepStrictEqual(privateKey.algorithm.publicExponent, publicExponent);
      assert.strictEqual(
        KeyObject.from(privateKey).asymmetricKeyDetails.publicExponent,
        bigIntArrayToUnsignedBigInt(publicExponent)
      );
      assert.strictEqual(privateKey.algorithm.hash.name, hash);

      // Missing parameters
      await assert.rejects(
        subtle.generateKey({ name, publicExponent, hash }, true, usages),
        {
          code: 'ERR_MISSING_OPTION',
        }
      );

      await assert.rejects(
        subtle.generateKey({ name, modulusLength, hash }, true, usages),
        {
          code: 'ERR_MISSING_OPTION',
        }
      );

      await assert.rejects(
        subtle.generateKey({ name, modulusLength }, true, usages),
        {
          code: 'ERR_MISSING_OPTION',
        }
      );

      await Promise.all(
        [{}].map((modulusLength) => {
          return assert.rejects(
            subtle.generateKey(
              {
                name,
                modulusLength,
                publicExponent,
                hash,
              },
              true,
              usages
            ),
            {
              code: 'ERR_INVALID_ARG_TYPE',
            }
          );
        })
      );

      await Promise.all(
        ['', true, {}, 1, [], new Uint32Array(2)].map((publicExponent) => {
          return assert.rejects(
            subtle.generateKey(
              { name, modulusLength, publicExponent, hash },
              true,
              usages
            ),
            { code: 'ERR_INVALID_ARG_TYPE' }
          );
        })
      );

      await Promise.all(
        [true, 1].map((hash) => {
          return assert.rejects(
            subtle.generateKey(
              {
                name,
                modulusLength,
                publicExponent,
                hash,
              },
              true,
              usages
            ),
            {
              message: /Unrecognized algorithm name/,
              name: 'NotSupportedError',
            }
          );
        })
      );

      await Promise.all(
        ['', {}, 1, false].map((usages) => {
          return assert.rejects(
            subtle.generateKey(
              {
                name,
                modulusLength,
                publicExponent,
                hash,
              },
              true,
              usages
            ),
            {
              code: 'ERR_INVALID_ARG_TYPE',
            }
          );
        })
      );

      await Promise.all(
        [[1], [1, 0, 0]].map((publicExponent) => {
          return assert.rejects(
            subtle.generateKey(
              {
                name,
                modulusLength,
                publicExponent: new Uint8Array(publicExponent),
                hash,
              },
              true,
              usages
            ),
            {
              name: 'OperationError',
            }
          );
        })
      );
    }

    const kTests = [
      [
        'RSASSA-PKCS1-v1_5',
        1024,
        Buffer.from([1, 0, 1]),
        'SHA-256',
        ['sign'],
        ['verify'],
      ],
      ['RSA-PSS', 2048, Buffer.from([1, 0, 1]), 'SHA-512', ['sign'], ['verify']],
      [
        'RSA-OAEP',
        1024,
        Buffer.from([3]),
        'SHA-384',
        ['decrypt', 'unwrapKey'],
        ['encrypt', 'wrapKey'],
      ],
    ];

    const tests = kTests.map((args) => test(...args));

    Promise.all(tests).then(common.mustCall());
  }
  */

  // Test EC Key Generation
  {
    async function testECKeyGen(
      name: AnyAlgorithm,
      namedCurve: NamedCurve,
      privateUsages: KeyUsage[],
      publicUsages: KeyUsage[] = privateUsages,
    ) {
      it(`EC keygen: ${name} ${namedCurve} ${privateUsages} ${publicUsages}`, async () => {
        let usages = privateUsages;
        if (publicUsages !== privateUsages) {
          usages = usages.concat(publicUsages);
        }

        const pair = await subtle.generateKey(
          {
            name,
            namedCurve,
          },
          true,
          usages,
        );
        const { publicKey, privateKey } = pair as CryptoKeyPair;
        const pub = publicKey as CryptoKey;
        const priv = privateKey as CryptoKey;

        expect(pub !== undefined);
        expect(priv !== undefined);
        expect(isCryptoKey(pub));
        expect(isCryptoKey(priv));
        expect(pub.type).to.equal('public');
        expect(priv.type).to.equal('private');
        expect(pub.keyExtractable).to.equal(true);
        expect(priv.keyExtractable).to.equal(true);
        expect(pub.keyUsages).to.deep.equal(publicUsages);
        expect(priv.keyUsages).to.deep.equal(privateUsages);
        expect(pub.algorithm.name, name);
        expect(priv.algorithm.name, name);
        expect(pub.algorithm.namedCurve, namedCurve);
        expect(priv.algorithm.namedCurve, namedCurve);

        // Invalid parameters
        [1, true, {}, [], null].forEach(async (curve) => {
          await assertThrowsAsync(
            async () =>
              await subtle.generateKey(
                // @ts-expect-error bad named curve
                { name, namedCurve: curve },
                true,
                privateUsages,
              ),
            'NotSupportedError',
          );
        });
        await assertThrowsAsync(
          async () =>
            subtle.generateKey(
              { name, namedCurve: undefined },
              true,
              privateUsages,
            ),
          "Unrecognized namedCurve 'undefined'",
        );
      });
    }

    testECKeyGen('ECDSA', 'P-384', ['sign'], ['verify']);
    testECKeyGen('ECDSA', 'P-521', ['sign'], ['verify']);
    testECKeyGen('ECDH', 'P-384', ['deriveKey', 'deriveBits'], []);
    testECKeyGen('ECDH', 'P-521', ['deriveKey', 'deriveBits'], []);
  }

  // Test AES Key Generation
  {
    type AESArgs = [AESAlgorithm, AESLength, KeyUsage[]];
    async function testAesKeyGen(args: AESArgs) {
      const [name, length, usages] = args;
      it(`AES keygen: ${name} ${length} ${usages}`, async () => {
        const key = await subtle.generateKey({ name, length }, true, usages);
        const k = key as CryptoKey;
        expect(k !== undefined);
        expect(isCryptoKey(k));

        expect(k.type).to.equal('secret');
        expect(k.extractable).to.equal(true);
        expect(k.usages).to.deep.equal(usages);
        expect(k.algorithm.name).to.equal(name);
        expect(k.algorithm.length).to.equal(length);

        // Invalid parameters
        [1, 100, 257, '', false, null, undefined].forEach(
          async (invalidParam) => {
            await assertThrowsAsync(
              async () =>
                subtle.generateKey(
                  // @ts-expect-error bad length
                  { name, length: invalidParam },
                  true,
                  usages,
                ),
              'AES key length must be 128, 192, or 256 bits',
            );
          },
        );
      });
    }

    const aesTests: AESArgs[] = [
      ['AES-CTR', 128, ['encrypt', 'decrypt', 'wrapKey']],
      ['AES-CTR', 256, ['encrypt', 'decrypt', 'unwrapKey']],
      ['AES-CBC', 128, ['encrypt', 'decrypt']],
      ['AES-CBC', 256, ['encrypt', 'decrypt']],
      ['AES-GCM', 128, ['encrypt', 'decrypt']],
      ['AES-GCM', 256, ['encrypt', 'decrypt']],
      ['AES-KW', 128, ['wrapKey', 'unwrapKey']],
      ['AES-KW', 256, ['wrapKey', 'unwrapKey']],
    ];

    aesTests.map((args) => testAesKeyGen(args));
  }

  /*
  // Test HMAC Key Generation
  {
    async function test(length, hash, usages) {
      const key = await subtle.generateKey(
        {
          name: 'HMAC',
          length,
          hash,
        },
        true,
        usages
      );

      if (length === undefined) {
        switch (hash) {
          case 'SHA-1':
            length = 512;
            break;
          case 'SHA-256':
            length = 512;
            break;
          case 'SHA-384':
            length = 1024;
            break;
          case 'SHA-512':
            length = 1024;
            break;
        }
      }

      assert(key);
      assert(isCryptoKey(key));

      assert.strictEqual(key.type, 'secret');
      assert.strictEqual(key.toString(), '[object CryptoKey]');
      assert.strictEqual(key.extractable, true);
      assert.deepStrictEqual(key.usages, usages);
      assert.strictEqual(key.algorithm.name, 'HMAC');
      assert.strictEqual(key.algorithm.length, length);
      assert.strictEqual(key.algorithm.hash.name, hash);

      [1, false, null].forEach(async (hash) => {
        await assert.rejects(
          subtle.generateKey({ name: 'HMAC', length, hash }, true, usages),
          {
            message: /Unrecognized algorithm name/,
            name: 'NotSupportedError',
          }
        );
      });
    }

    const kTests = [
      [undefined, 'SHA-1', ['sign', 'verify']],
      [undefined, 'SHA-256', ['sign', 'verify']],
      [undefined, 'SHA-384', ['sign', 'verify']],
      [undefined, 'SHA-512', ['sign', 'verify']],
      [128, 'SHA-256', ['sign', 'verify']],
      [1024, 'SHA-512', ['sign', 'verify']],
    ];

    const tests = Promise.all(kTests.map((args) => test(...args)));

    tests.then(common.mustCall());
  }

  // End user code cannot create CryptoKey directly
  assert.throws(() => new CryptoKey(), { code: 'ERR_ILLEGAL_CONSTRUCTOR' });

  {
    const buffer = Buffer.from('Hello World');
    const keyObject = createSecretKey(buffer);
    assert(!isCryptoKey(buffer));
    assert(!isCryptoKey(keyObject));
  }

  // Test OKP Key Generation
  {
    async function test(name, privateUsages, publicUsages = privateUsages) {
      let usages = privateUsages;
      if (publicUsages !== privateUsages) usages = usages.concat(publicUsages);

      const { publicKey, privateKey } = await subtle.generateKey(
        {
          name,
        },
        true,
        usages
      );

      assert(publicKey);
      assert(privateKey);
      assert(isCryptoKey(publicKey));
      assert(isCryptoKey(privateKey));

      assert.strictEqual(publicKey.type, 'public');
      assert.strictEqual(privateKey.type, 'private');
      assert.strictEqual(publicKey.toString(), '[object CryptoKey]');
      assert.strictEqual(privateKey.toString(), '[object CryptoKey]');
      assert.strictEqual(publicKey.extractable, true);
      assert.strictEqual(privateKey.extractable, true);
      assert.deepStrictEqual(publicKey.usages, publicUsages);
      assert.deepStrictEqual(privateKey.usages, privateUsages);
      assert.strictEqual(publicKey.algorithm.name, name);
      assert.strictEqual(privateKey.algorithm.name, name);
    }

    const kTests = [
      ['Ed25519', ['sign'], ['verify']],
      ['Ed448', ['sign'], ['verify']],
      ['X25519', ['deriveKey', 'deriveBits'], []],
      ['X448', ['deriveKey', 'deriveBits'], []],
    ];

    const tests = kTests.map((args) => test(...args));

    // Test bad parameters

    Promise.all(tests).then(common.mustCall());
  }
  */
});
