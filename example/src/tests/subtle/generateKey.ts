/* eslint-disable @typescript-eslint/no-explicit-any */
import { expect } from 'chai';
import {
  subtle,
  // type AESAlgorithm,
  // type AESLength,
  type AnyAlgorithm,
  type NamedCurve,
} from 'react-native-quick-crypto';
import type { CryptoKey, KeyUsage } from 'react-native-quick-crypto';

// Local interface to match what subtle.generateKey actually returns
interface TestCryptoKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}
import { test, assertThrowsAsync } from '../util';

const SUITE = 'subtle.generateKey';

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
  // HMAC: {
  //   algorithm: { length: 256, hash: 'SHA-256' },
  //   result: 'CryptoKey',
  //   usages: ['sign', 'verify'],
  // },
  'RSASSA-PKCS1-v1_5': {
    algorithm: {
      modulusLength: 1024,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    result: 'CryptoKeyPair',
    usages: ['sign', 'verify'],
  },
  'RSA-PSS': {
    algorithm: {
      modulusLength: 1024,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    result: 'CryptoKeyPair',
    usages: ['sign', 'verify'],
  },
  'RSA-OAEP': {
    algorithm: {
      modulusLength: 1024,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    result: 'CryptoKeyPair',
    usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  },
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
  // Ed25519: {
  //   result: 'CryptoKeyPair',
  //   usages: ['sign', 'verify'],
  // },
  // Ed448: {
  //   result: 'CryptoKeyPair',
  //   usages: ['sign', 'verify'],
  // },
  // X25519: {
  //   result: 'CryptoKeyPair',
  //   usages: ['deriveKey', 'deriveBits'],
  // },
  // X448: {
  //   result: 'CryptoKeyPair',
  //   usages: ['deriveKey', 'deriveBits'],
  // },
};

// Test invalid algorithms
async function testInvalidAlgorithm(algorithm: any) {
  // Tests with invalid hash algorithms get a different error message
  const errorText =
    algorithm.hash === 'SHA' || algorithm.hash === 'MD5'
      ? 'Invalid Hash Algorithm'
      : 'Unrecognized algorithm name';
  const algo = JSON.stringify(algorithm);
  test(SUITE, `invalid algo: ${algo}`, async () => {
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

// Test bad usages
async function testBadUsage(name: string) {
  test(SUITE, `bad usages: ${name}`, async () => {
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
    allUsages.forEach(usage => {
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

// Test EC Key Generation
async function testECKeyGen(
  name: AnyAlgorithm,
  namedCurve: NamedCurve,
  privateUsages: KeyUsage[],
  publicUsages: KeyUsage[] = privateUsages,
) {
  test(
    SUITE,
    `EC keygen: ${name} ${namedCurve} ${privateUsages} ${publicUsages}`,
    async () => {
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
      const { publicKey, privateKey } = pair as TestCryptoKeyPair;
      const pub = publicKey;
      const priv = privateKey;

      expect(pub !== undefined);
      expect(priv !== undefined);
      expect(pub instanceof Object);
      expect(priv instanceof Object);
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
      [1, true, {}, [], null].forEach(async curve => {
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
    },
  );
}

testECKeyGen('ECDSA', 'P-384', ['sign'], ['verify']);
testECKeyGen('ECDSA', 'P-521', ['sign'], ['verify']);
testECKeyGen('ECDH', 'P-384', ['deriveKey', 'deriveBits'], []);
testECKeyGen('ECDH', 'P-521', ['deriveKey', 'deriveBits'], []);

// Test RSA Key Generation
async function testRSAKeyGen(
  name: 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' | 'RSA-OAEP',
  modulusLength: number,
  publicExponent: Uint8Array,
  hash: string,
  privateUsages: KeyUsage[],
  publicUsages: KeyUsage[] = privateUsages,
) {
  test(
    SUITE,
    `RSA keygen: ${name} ${modulusLength} ${hash} ${privateUsages} ${publicUsages}`,
    async () => {
      let usages = privateUsages;
      if (publicUsages !== privateUsages) {
        usages = usages.concat(publicUsages);
      }

      const keyPair = await subtle.generateKey(
        {
          name,
          modulusLength,
          publicExponent,
          hash,
        } as any,
        true,
        usages,
      );

      const { publicKey, privateKey } = keyPair as TestCryptoKeyPair;
      expect(publicKey !== undefined);
      expect(privateKey !== undefined);
      expect(publicKey instanceof Object);
      expect(privateKey instanceof Object);

      expect(publicKey.type).to.equal('public');
      expect(privateKey.type).to.equal('private');
      expect(publicKey.extractable).to.equal(true);
      expect(privateKey.extractable).to.equal(true);
      expect(publicKey.usages).to.deep.equal(publicUsages);
      expect(privateKey.usages).to.deep.equal(privateUsages);
      expect(publicKey.algorithm.name).to.equal(name);
      expect(privateKey.algorithm.name).to.equal(name);
      expect((publicKey.algorithm as any).modulusLength).to.equal(
        modulusLength,
      );
      expect((privateKey.algorithm as any).modulusLength).to.equal(
        modulusLength,
      );
      expect((publicKey.algorithm as any).publicExponent).to.deep.equal(
        publicExponent,
      );
      expect((privateKey.algorithm as any).publicExponent).to.deep.equal(
        publicExponent,
      );
      expect((publicKey.algorithm as any).hash.name).to.equal(hash);
      expect((privateKey.algorithm as any).hash.name).to.equal(hash);

      // Test invalid usage
      await assertThrowsAsync(
        async () =>
          subtle.generateKey(
            { name, modulusLength, publicExponent, hash } as any,
            true,
            name === 'RSA-OAEP' ? ['sign'] : ['encrypt'],
          ),
        `Unsupported key usage for a ${name} key`,
      );

      // Test invalid modulus length
      await assertThrowsAsync(
        async () =>
          subtle.generateKey(
            { name, modulusLength: 0, publicExponent, hash } as any,
            true,
            usages,
          ),
        'Invalid key length',
      );
    },
  );
}

testRSAKeyGen(
  'RSASSA-PKCS1-v1_5',
  1024,
  new Uint8Array([1, 0, 1]),
  'SHA-256',
  ['sign'],
  ['verify'],
);
testRSAKeyGen(
  'RSA-PSS',
  2048,
  new Uint8Array([1, 0, 1]),
  'SHA-512',
  ['sign'],
  ['verify'],
);
testRSAKeyGen(
  'RSA-OAEP',
  1024,
  new Uint8Array([3]),
  'SHA-384',
  ['decrypt', 'unwrapKey'],
  ['encrypt', 'wrapKey'],
);

// --- X25519/X448 Key Generation Tests (from subtle.cfrg suite) ---

test(
  SUITE,
  'X25519 - generateKey, exportKey, importKey, deriveBits',
  async () => {
    const format = 'raw';
    const algorithm = { name: 'X25519' } as const;

    const aliceKeys = (await subtle.generateKey(algorithm, true, [
      'deriveKey',
      'deriveBits',
    ])) as TestCryptoKeyPair;

    const bobKeys = (await subtle.generateKey(algorithm, true, [
      'deriveKey',
      'deriveBits',
    ])) as TestCryptoKeyPair;

    expect(aliceKeys.publicKey.algorithm.name).to.equal('X25519');
    expect(aliceKeys.privateKey.algorithm.name).to.equal('X25519');

    const alicePubRaw = await subtle.exportKey(format, aliceKeys.publicKey);
    const bobPubRaw = await subtle.exportKey(format, bobKeys.publicKey);

    const alicePubImported = await subtle.importKey(
      format,
      alicePubRaw,
      algorithm,
      true,
      [],
    );

    const bobPubImported = await subtle.importKey(
      format,
      bobPubRaw,
      algorithm,
      true,
      [],
    );

    const bitsLength = 256;
    const aliceShared = await subtle.deriveBits(
      { name: 'X25519', public: bobPubImported } as any,
      aliceKeys.privateKey,
      bitsLength,
    );

    const bobShared = await subtle.deriveBits(
      { name: 'X25519', public: alicePubImported } as any,
      bobKeys.privateKey,
      bitsLength,
    );

    const aliceSharedView = new Uint8Array(aliceShared);
    const bobSharedView = new Uint8Array(bobShared);

    expect(aliceSharedView.length).to.equal(bitsLength / 8);
    expect(aliceSharedView).to.deep.equal(bobSharedView);
  },
);

test(
  SUITE,
  'X448 - generateKey, exportKey, importKey, deriveBits',
  async () => {
    const format = 'spki';
    const algorithm = { name: 'X448' } as const;

    const aliceKeys = (await subtle.generateKey(algorithm, true, [
      'deriveKey',
      'deriveBits',
    ])) as TestCryptoKeyPair;

    const bobKeys = (await subtle.generateKey(algorithm, true, [
      'deriveKey',
      'deriveBits',
    ])) as TestCryptoKeyPair;

    expect(aliceKeys.publicKey.algorithm.name).to.equal('X448');
    expect(aliceKeys.privateKey.algorithm.name).to.equal('X448');

    const alicePubSpki = await subtle.exportKey(format, aliceKeys.publicKey);
    const bobPubSpki = await subtle.exportKey(format, bobKeys.publicKey);

    const alicePubImported = await subtle.importKey(
      format,
      alicePubSpki,
      algorithm,
      true,
      [],
    );

    const bobPubImported = await subtle.importKey(
      format,
      bobPubSpki,
      algorithm,
      true,
      [],
    );

    const bitsLength = 448;
    const aliceShared = await subtle.deriveBits(
      { name: 'X448', public: bobPubImported } as any,
      aliceKeys.privateKey,
      bitsLength,
    );

    const bobShared = await subtle.deriveBits(
      { name: 'X448', public: alicePubImported } as any,
      bobKeys.privateKey,
      bitsLength,
    );

    const aliceSharedView = new Uint8Array(aliceShared);
    const bobSharedView = new Uint8Array(bobShared);

    expect(aliceSharedView.length).to.equal(56);
    expect(aliceSharedView).to.deep.equal(bobSharedView);
  },
);

// --- ML-DSA Key Generation Tests ---

type MlDsaVariant = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
const MLDSA_VARIANTS: MlDsaVariant[] = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];

interface TestCryptoKeyPairMlDsa {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

for (const variant of MLDSA_VARIANTS) {
  test(SUITE, `ML-DSA keygen: ${variant}`, async () => {
    const keyPair = await subtle.generateKey({ name: variant }, true, [
      'sign',
      'verify',
    ]);

    const { publicKey, privateKey } = keyPair as TestCryptoKeyPairMlDsa;

    expect(publicKey !== undefined);
    expect(privateKey !== undefined);
    expect(publicKey instanceof Object);
    expect(privateKey instanceof Object);
    expect(publicKey.type).to.equal('public');
    expect(privateKey.type).to.equal('private');
    expect(publicKey.extractable).to.equal(true);
    expect(privateKey.extractable).to.equal(true);
    expect(publicKey.usages).to.deep.equal(['verify']);
    expect(privateKey.usages).to.deep.equal(['sign']);
    expect(publicKey.algorithm.name).to.equal(variant);
    expect(privateKey.algorithm.name).to.equal(variant);
  });

  test(SUITE, `ML-DSA keygen non-extractable: ${variant}`, async () => {
    const keyPair = await subtle.generateKey({ name: variant }, false, [
      'sign',
      'verify',
    ]);

    const { publicKey, privateKey } = keyPair as TestCryptoKeyPairMlDsa;

    // Public key is always extractable
    expect(publicKey.extractable).to.equal(true);
    // Private key respects extractable parameter
    expect(privateKey.extractable).to.equal(false);
  });
}

// Test bad usages for ML-DSA
test(SUITE, 'ML-DSA bad usages', async () => {
  await assertThrowsAsync(
    async () => await subtle.generateKey({ name: 'ML-DSA-44' }, true, []),
    'Usages cannot be empty',
  );

  await assertThrowsAsync(
    async () =>
      await subtle.generateKey({ name: 'ML-DSA-44' }, true, ['encrypt']),
    'Unsupported key usage',
  );
});

/*
// Test AES Key Generation
type AESArgs = [AESAlgorithm, AESLength, KeyUsage[]];
async function testAesKeyGen(args: AESArgs) {
  const [name, length, usages] = args;
  test(SUITE, `AES keygen: ${name} ${length} ${usages}`, async () => {
    const key = await subtle.generateKey({ name, length }, true, usages);
    const k = key as CryptoKey;
    expect(k !== undefined);
    expect(k instanceof Object);

    expect(k.type).to.equal('secret');
    expect(k.extractable).to.equal(true);
    expect(k.usages).to.deep.equal(usages);
    expect(k.algorithm.name).to.equal(name);
    expect(k.algorithm.length).to.equal(length);

    // Invalid parameters
    [1, 100, 257, '', false, null, undefined].forEach(async invalidParam => {
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
    });
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

aesTests.map(args => testAesKeyGen(args));
*/

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
