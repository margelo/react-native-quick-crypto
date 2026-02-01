import {
  Buffer,
  createSecretKey,
  createPrivateKey,
  createPublicKey,
  generateKeyPair,
  randomBytes,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test, assertThrowsAsync, decodeHex } from '../util';
import { rsaPrivateKeyPem, rsaPublicKeyPem } from './fixtures';

const SUITE = 'keys.createKey';

// RSA 2048-bit test keys in DER format
// Source: Node.js test fixtures / WebCrypto test vectors
const pkcs8Der = decodeHex(
  '308204bf020100300d06092a864886f70d0101010500048204a930820' +
    '4a50201000282010100d3576092e62957364544e7e4233b7bdb293db2' +
    '085122c479328546f9f0f712f657c4b17868c930908cc594f7ed00c01' +
    '442c1af04c2f678a48ba2c80fd1713e30b5ac50787ac3516589f17196' +
    '7f6386ada34900a6bb04eecea42bf043ced9a0f94d0cc09e919b9d716' +
    '6c08ab6ce204640aea4c4920db6d86eb916d0dcc0f4341a10380429e7' +
    'e1032144ea949de8f6c0ccbf95fa8e928d70d8a38ce168db45f6f1346' +
    '63d6f656f5ceabc725da8c02aabeaaa13ac36a75cc0bae135df3114b6' +
    '6589c7ed3cb61559ae5a384f162bfa80dbe4617f86c3f1d010c94fe2c' +
    '9bf019a6e63b3efc028d43cee611c85ec263c906c463772c6911b19ee' +
    'c096ca76ec5e31e1e3020301000102820101008b375ccb87c825c5ff3' +
    'd53d009916e9641057e18527227a07ab226be1088813a3b38bb7b48f3' +
    '77055165fa2a9339d24dc667d5c5ba3427e6a481176eac15ffd490683' +
    '11e1c283b9f3a8e0cb809b4630c50aa8f3e45a60b359e19bf8cbb5eca' +
    'd64e761f1095743ff36aaf5cf0ecb97fedaddda60b5bf35d811a75b82' +
    '2230cfaa0192fad40547e275448aa3316bf8e2b4ce0854fc7708b537b' +
    'a22d13210b09aec37a2759efc082a1531b23a91730037dde4ef26b5f9' +
    '6efdcc39fd34c345ad51cbbe44fe58b8a3b4ec997866c086dff1b8831' +
    'ef0a1fea263cf7dacd03c04cbcc2b279e57fa5b953996bfb1dd68817a' +
    'f7fb42cdef7a5294a57fac2b8ad739f1b029902818100fbf833c2c631' +
    'c970240c8e7485f06a3ea2a84822511a8627dd464ef8afaf7148d1a42' +
    '5b6b8657ddd5246832b8e533020c5bbb568855a6aec3e4221d793f1dc' +
    '5b2f2584e2415e48e9a2bd292b134031f99c8eb42fc0bcd0449bf22ce' +
    '6dec97014efe5ac93ebe835877656252cbbb16c415b67b184d2284568' +
    'a277d59335585cfd02818100d6b8ce27c7295d5d16fc3570ed64c8da9' +
    '303fad29488c1a65e9ad711f90370187dbbfd81316d69648bc88cc5c8' +
    '3551afff45debacfb61105f709e4c30809b90031ebd686244496c6f69' +
    'e692ebdc814f64239f4ad15756ecb78c5a5b09931db183077c546a38c' +
    '4c743889ad3d3ed079b5622ed0120fa0e1f93b593db7d852e05f02818' +
    '038874b9d83f78178ce2d9efc175c83897fd67f306bbfa69f64ee3423' +
    '68ced47c80c3f1ce177a758d64bafb0c9786a44285fa01cdec3507cde' +
    'e7dc9b7e2b21d3cbbcc100eee9967843b057329fdcca62998ed0f11b3' +
    '8ce8b0abc7de39017c71cfd0ae57546c559144cdd0afd0645f7ea8ff0' +
    '7b974d1ed44fd1f8e00f560bf6d45028181008529ef9073cf8f7b5ff9' +
    'e21abadf3a4173d3900670dfaf59426abcdf0493c13d2f1d1b46b824a' +
    '6ac1894b3d925250c181e3472c16078056eb19a8d28f71f3080927534' +
    '81d49444fdf78c9ea6c24407dc018e77d3afef385b2ff7439e9623794' +
    '1332dd446cebeffdb4404fe4f71595161d016402c334d0f57c61abe4f' +
    'f9f4cbf90281810087d87708d46763e4ccbeb2d1e9712e5bf0216d70d' +
    'e9420a5b2069b7459b99f5d9f7f2fad7cd79aaee67a7f9a34437e3c79' +
    'a84af0cd8de9dff268eb0c4793f501f988d540f6d3475c2079b8227a2' +
    '3d968dec4e3c66503187193459630472bfdb6ba1de786c797fa6f4ea6' +
    '5a2a8419262f29678856cb73c9bd4bc89b5e041b2277',
);

const spkiDer = decodeHex(
  '30820122300d06092a864886f70d01010105000382010f003082010a0' +
    '282010100d3576092e62957364544e7e4233b7bdb293db2085122c479' +
    '328546f9f0f712f657c4b17868c930908cc594f7ed00c01442c1af04c' +
    '2f678a48ba2c80fd1713e30b5ac50787ac3516589f171967f6386ada3' +
    '4900a6bb04eecea42bf043ced9a0f94d0cc09e919b9d7166c08ab6ce2' +
    '04640aea4c4920db6d86eb916d0dcc0f4341a10380429e7e1032144ea' +
    '949de8f6c0ccbf95fa8e928d70d8a38ce168db45f6f134663d6f656f5' +
    'ceabc725da8c02aabeaaa13ac36a75cc0bae135df3114b66589c7ed3c' +
    'b61559ae5a384f162bfa80dbe4617f86c3f1d010c94fe2c9bf019a6e6' +
    '3b3efc028d43cee611c85ec263c906c463772c6911b19eec096ca76ec' +
    '5e31e1e30203010001',
);

// --- createSecretKey Tests ---

test(SUITE, 'createSecretKey from Buffer', () => {
  const keyData = randomBytes(32);
  const key = createSecretKey(keyData);

  expect(key.type).to.equal('secret');
});

test(SUITE, 'createSecretKey from Uint8Array', () => {
  const keyData = new Uint8Array(randomBytes(32));
  const key = createSecretKey(keyData);

  expect(key.type).to.equal('secret');
});

test(SUITE, 'createSecretKey 128-bit key', () => {
  const keyData = randomBytes(16);
  const key = createSecretKey(keyData);

  expect(key.type).to.equal('secret');
});

test(SUITE, 'createSecretKey 256-bit key', () => {
  const keyData = randomBytes(32);
  const key = createSecretKey(keyData);

  expect(key.type).to.equal('secret');
});

test(SUITE, 'createSecretKey export and reimport', () => {
  const keyData = randomBytes(32);
  const key = createSecretKey(keyData);

  const exported = key.export();
  const reimported = createSecretKey(exported);

  expect(reimported.type).to.equal('secret');
  expect(Buffer.compare(reimported.export(), keyData)).to.equal(0);
});

// --- createPublicKey Tests ---

test(SUITE, 'createPublicKey from PEM string', () => {
  const key = createPublicKey(rsaPublicKeyPem);

  expect(key.type).to.equal('public');
  expect(key.asymmetricKeyType).to.equal('rsa');
});

test(SUITE, 'createPublicKey from DER buffer (SPKI)', () => {
  const key = createPublicKey({
    key: Buffer.from(spkiDer),
    format: 'der',
    type: 'spki',
  });

  expect(key.type).to.equal('public');
  expect(key.asymmetricKeyType).to.equal('rsa');
});

test(SUITE, 'createPublicKey extracts public from private key', () => {
  const privateKey = createPrivateKey(rsaPrivateKeyPem);
  const publicKey = createPublicKey(privateKey);

  expect(publicKey.type).to.equal('public');
  expect(publicKey.asymmetricKeyType).to.equal('rsa');
});

test(SUITE, 'createPublicKey from generateKeyPair', async () => {
  const { publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'rsa',
      {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      },
      (err, pubKey, privKey) => {
        if (err) reject(err);
        else
          resolve({
            privateKey: privKey as string,
            publicKey: pubKey as string,
          });
      },
    );
  });

  const key = createPublicKey(publicKey);

  expect(key.type).to.equal('public');
  expect(key.asymmetricKeyType).to.equal('rsa');
});

test(SUITE, 'createPublicKey EC P-256', async () => {
  const { publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'ec',
      {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      },
      (err, pubKey, privKey) => {
        if (err) reject(err);
        else
          resolve({
            privateKey: privKey as string,
            publicKey: pubKey as string,
          });
      },
    );
  });

  const key = createPublicKey(publicKey);

  expect(key.type).to.equal('public');
  expect(key.asymmetricKeyType).to.equal('ec');
});

test(SUITE, 'createPublicKey Ed25519', async () => {
  const { publicKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'ed25519',
      {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      },
      (err, pubKey, privKey) => {
        if (err) reject(err);
        else
          resolve({
            privateKey: privKey as string,
            publicKey: pubKey as string,
          });
      },
    );
  });

  const key = createPublicKey(publicKey);

  expect(key.type).to.equal('public');
  expect(key.asymmetricKeyType).to.equal('ed25519');
});

// --- createPrivateKey Tests ---

test(SUITE, 'createPrivateKey from PEM string', () => {
  const key = createPrivateKey(rsaPrivateKeyPem);

  expect(key.type).to.equal('private');
  expect(key.asymmetricKeyType).to.equal('rsa');
});

test(SUITE, 'createPrivateKey from DER buffer (PKCS8)', () => {
  const key = createPrivateKey({
    key: Buffer.from(pkcs8Der),
    format: 'der',
    type: 'pkcs8',
  });

  expect(key.type).to.equal('private');
  expect(key.asymmetricKeyType).to.equal('rsa');
});

test(SUITE, 'createPrivateKey from generateKeyPair', async () => {
  const { privateKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'rsa',
      {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      },
      (err, pubKey, privKey) => {
        if (err) reject(err);
        else
          resolve({
            privateKey: privKey as string,
            publicKey: pubKey as string,
          });
      },
    );
  });

  const key = createPrivateKey(privateKey);

  expect(key.type).to.equal('private');
  expect(key.asymmetricKeyType).to.equal('rsa');
});

test(SUITE, 'createPrivateKey EC P-256', async () => {
  const { privateKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'ec',
      {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      },
      (err, pubKey, privKey) => {
        if (err) reject(err);
        else
          resolve({
            privateKey: privKey as string,
            publicKey: pubKey as string,
          });
      },
    );
  });

  const key = createPrivateKey(privateKey);

  expect(key.type).to.equal('private');
  expect(key.asymmetricKeyType).to.equal('ec');
});

test(SUITE, 'createPrivateKey Ed25519', async () => {
  const { privateKey } = await new Promise<{
    privateKey: string;
    publicKey: string;
  }>((resolve, reject) => {
    generateKeyPair(
      'ed25519',
      {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      },
      (err, pubKey, privKey) => {
        if (err) reject(err);
        else
          resolve({
            privateKey: privKey as string,
            publicKey: pubKey as string,
          });
      },
    );
  });

  const key = createPrivateKey(privateKey);

  expect(key.type).to.equal('private');
  expect(key.asymmetricKeyType).to.equal('ed25519');
});

// --- Round-Trip Tests ---

test(SUITE, 'RSA key round-trip: create -> export -> create', () => {
  const originalPrivate = createPrivateKey(rsaPrivateKeyPem);
  const exportedPrivate = originalPrivate.export({
    type: 'pkcs8',
    format: 'pem',
  });
  const reimportedPrivate = createPrivateKey(exportedPrivate as string);

  expect(reimportedPrivate.type).to.equal('private');
  expect(reimportedPrivate.asymmetricKeyType).to.equal('rsa');
});

test(
  SUITE,
  'EC key round-trip: generateKeyPair -> createPrivateKey -> export -> createPrivateKey',
  async () => {
    const { privateKey } = await new Promise<{
      privateKey: string;
      publicKey: string;
    }>((resolve, reject) => {
      generateKeyPair(
        'ec',
        {
          namedCurve: 'P-384',
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        },
        (err, pubKey, privKey) => {
          if (err) reject(err);
          else
            resolve({
              privateKey: privKey as string,
              publicKey: pubKey as string,
            });
        },
      );
    });

    const key1 = createPrivateKey(privateKey);
    const exported = key1.export({ type: 'pkcs8', format: 'pem' });
    const key2 = createPrivateKey(exported as string);

    expect(key2.type).to.equal('private');
    expect(key2.asymmetricKeyType).to.equal('ec');
  },
);

// --- Error Cases ---

test(SUITE, 'createPublicKey throws with invalid PEM', async () => {
  await assertThrowsAsync(async () => {
    createPublicKey('not a valid PEM key');
  }, '');
});

test(SUITE, 'createPrivateKey throws with invalid PEM', async () => {
  await assertThrowsAsync(async () => {
    createPrivateKey('not a valid PEM key');
  }, '');
});

test(
  SUITE,
  'createPublicKey throws with private key PEM (wrong type)',
  async () => {
    await assertThrowsAsync(async () => {
      createPublicKey({
        key: rsaPrivateKeyPem,
        format: 'pem',
        type: 'spki', // Wrong type for private key
      });
    }, '');
  },
);
