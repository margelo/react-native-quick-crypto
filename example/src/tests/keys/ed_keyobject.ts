import {
  generateKeyPairSync,
  generateKeyPair,
  createPrivateKey,
  createPublicKey,
  KeyObject,
  AsymmetricKeyObject,
  Buffer,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';

const SUITE = 'keys.edKeyObject';

// --- Ed25519 KeyObject tests ---

test(SUITE, 'generateKeyPairSync ed25519 returns KeyObjects', () => {
  const result = generateKeyPairSync('ed25519');
  const pub = result.publicKey as InstanceType<typeof AsymmetricKeyObject>;
  const priv = result.privateKey as InstanceType<typeof AsymmetricKeyObject>;

  expect(pub).to.be.an.instanceOf(KeyObject);
  expect(priv).to.be.an.instanceOf(KeyObject);
  expect(pub.type).to.equal('public');
  expect(priv.type).to.equal('private');
  expect(pub.asymmetricKeyType).to.equal('ed25519');
  expect(priv.asymmetricKeyType).to.equal('ed25519');
});

test(SUITE, 'ed25519 KeyObject.export() works for PEM', () => {
  const result = generateKeyPairSync('ed25519');
  const pub = result.publicKey as InstanceType<typeof AsymmetricKeyObject>;
  const priv = result.privateKey as InstanceType<typeof AsymmetricKeyObject>;

  const pubPem = pub.export({ type: 'spki', format: 'pem' });
  const privPem = priv.export({ type: 'pkcs8', format: 'pem' });

  expect(typeof pubPem).to.equal('string');
  expect(typeof privPem).to.equal('string');
  expect(pubPem as string).to.match(/^-----BEGIN PUBLIC KEY-----/);
  expect(privPem as string).to.match(/^-----BEGIN PRIVATE KEY-----/);
});

test(SUITE, 'ed25519 KeyObject.export() works for DER', () => {
  const result = generateKeyPairSync('ed25519');
  const pub = result.publicKey as InstanceType<typeof AsymmetricKeyObject>;
  const priv = result.privateKey as InstanceType<typeof AsymmetricKeyObject>;

  const pubDer = pub.export({ type: 'spki', format: 'der' });
  const privDer = priv.export({ type: 'pkcs8', format: 'der' });

  expect(Buffer.isBuffer(pubDer)).to.equal(true);
  expect(Buffer.isBuffer(privDer)).to.equal(true);
});

test(SUITE, 'ed25519 with PEM encoding returns strings', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  expect(typeof publicKey).to.equal('string');
  expect(typeof privateKey).to.equal('string');
  expect(publicKey as string).to.match(/^-----BEGIN PUBLIC KEY-----/);
  expect(privateKey as string).to.match(/^-----BEGIN PRIVATE KEY-----/);
});

test(SUITE, 'ed25519 with DER encoding returns ArrayBuffers', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });

  expect(publicKey instanceof ArrayBuffer).to.equal(true);
  expect(privateKey instanceof ArrayBuffer).to.equal(true);
  expect((publicKey as ArrayBuffer).byteLength).to.be.greaterThan(0);
  expect((privateKey as ArrayBuffer).byteLength).to.be.greaterThan(0);
});

// --- Round-trip tests ---

test(
  SUITE,
  'ed25519 round-trip: KeyObject -> export DER -> createKey -> export',
  () => {
    const result = generateKeyPairSync('ed25519');
    const pub = result.publicKey as InstanceType<typeof AsymmetricKeyObject>;
    const priv = result.privateKey as InstanceType<typeof AsymmetricKeyObject>;

    const privDer = priv.export({ type: 'pkcs8', format: 'der' });
    const pubDer = pub.export({ type: 'spki', format: 'der' });

    const recreatedPriv = createPrivateKey({
      key: privDer,
      format: 'der',
      type: 'pkcs8',
    });
    const recreatedPub = createPublicKey({
      key: pubDer,
      format: 'der',
      type: 'spki',
    });

    expect(recreatedPriv.type).to.equal('private');
    expect(recreatedPub.type).to.equal('public');
    expect(recreatedPriv.asymmetricKeyType).to.equal('ed25519');
    expect(recreatedPub.asymmetricKeyType).to.equal('ed25519');

    const reExportedPriv = recreatedPriv.export({
      type: 'pkcs8',
      format: 'der',
    });
    const reExportedPub = recreatedPub.export({ type: 'spki', format: 'der' });

    expect(Buffer.compare(privDer, reExportedPriv)).to.equal(0);
    expect(Buffer.compare(pubDer, reExportedPub)).to.equal(0);
  },
);

test(
  SUITE,
  'ed25519 round-trip: KeyObject -> export PEM -> createKey -> export',
  () => {
    const result = generateKeyPairSync('ed25519');
    const pub = result.publicKey as InstanceType<typeof AsymmetricKeyObject>;
    const priv = result.privateKey as InstanceType<typeof AsymmetricKeyObject>;

    const privPem = priv.export({
      type: 'pkcs8',
      format: 'pem',
    }) as string;
    const pubPem = pub.export({ type: 'spki', format: 'pem' }) as string;

    const recreatedPriv = createPrivateKey(privPem);
    const recreatedPub = createPublicKey(pubPem);

    expect(recreatedPriv.asymmetricKeyType).to.equal('ed25519');
    expect(recreatedPub.asymmetricKeyType).to.equal('ed25519');

    const reExportedPriv = recreatedPriv.export({
      type: 'pkcs8',
      format: 'pem',
    }) as string;
    const reExportedPub = recreatedPub.export({
      type: 'spki',
      format: 'pem',
    }) as string;

    expect(reExportedPriv).to.equal(privPem);
    expect(reExportedPub).to.equal(pubPem);
  },
);

// --- Ed448 KeyObject tests ---

test(SUITE, 'generateKeyPairSync ed448 returns KeyObjects', () => {
  const result = generateKeyPairSync('ed448');
  const pub = result.publicKey as InstanceType<typeof AsymmetricKeyObject>;
  const priv = result.privateKey as InstanceType<typeof AsymmetricKeyObject>;

  expect(pub).to.be.an.instanceOf(KeyObject);
  expect(priv).to.be.an.instanceOf(KeyObject);
  expect(pub.asymmetricKeyType).to.equal('ed448');
  expect(priv.asymmetricKeyType).to.equal('ed448');
});

test(SUITE, 'ed448 round-trip: KeyObject -> export -> recreate', () => {
  const result = generateKeyPairSync('ed448');
  const pub = result.publicKey as InstanceType<typeof AsymmetricKeyObject>;
  const priv = result.privateKey as InstanceType<typeof AsymmetricKeyObject>;

  const privDer = priv.export({ type: 'pkcs8', format: 'der' });
  const pubDer = pub.export({ type: 'spki', format: 'der' });

  const recreatedPriv = createPrivateKey({
    key: privDer,
    format: 'der',
    type: 'pkcs8',
  });
  const recreatedPub = createPublicKey({
    key: pubDer,
    format: 'der',
    type: 'spki',
  });

  expect(recreatedPriv.asymmetricKeyType).to.equal('ed448');
  expect(recreatedPub.asymmetricKeyType).to.equal('ed448');
});

// --- X25519 KeyObject tests ---

test(SUITE, 'generateKeyPairSync x25519 returns KeyObjects', () => {
  const result = generateKeyPairSync('x25519');
  const pub = result.publicKey as InstanceType<typeof AsymmetricKeyObject>;
  const priv = result.privateKey as InstanceType<typeof AsymmetricKeyObject>;

  expect(pub).to.be.an.instanceOf(KeyObject);
  expect(priv).to.be.an.instanceOf(KeyObject);
  expect(pub.asymmetricKeyType).to.equal('x25519');
  expect(priv.asymmetricKeyType).to.equal('x25519');
});

test(SUITE, 'x25519 round-trip: KeyObject -> export -> recreate', () => {
  const result = generateKeyPairSync('x25519');
  const pub = result.publicKey as InstanceType<typeof AsymmetricKeyObject>;
  const priv = result.privateKey as InstanceType<typeof AsymmetricKeyObject>;

  const privDer = priv.export({ type: 'pkcs8', format: 'der' });
  const pubDer = pub.export({ type: 'spki', format: 'der' });

  const recreatedPriv = createPrivateKey({
    key: privDer,
    format: 'der',
    type: 'pkcs8',
  });
  const recreatedPub = createPublicKey({
    key: pubDer,
    format: 'der',
    type: 'spki',
  });

  expect(recreatedPriv.asymmetricKeyType).to.equal('x25519');
  expect(recreatedPub.asymmetricKeyType).to.equal('x25519');
});

// --- X448 KeyObject tests ---

test(SUITE, 'generateKeyPairSync x448 returns KeyObjects', () => {
  const result = generateKeyPairSync('x448');
  const pub = result.publicKey as InstanceType<typeof AsymmetricKeyObject>;
  const priv = result.privateKey as InstanceType<typeof AsymmetricKeyObject>;

  expect(pub).to.be.an.instanceOf(KeyObject);
  expect(priv).to.be.an.instanceOf(KeyObject);
  expect(pub.asymmetricKeyType).to.equal('x448');
  expect(priv.asymmetricKeyType).to.equal('x448');
});

test(SUITE, 'x448 round-trip: KeyObject -> export -> recreate', () => {
  const result = generateKeyPairSync('x448');
  const pub = result.publicKey as InstanceType<typeof AsymmetricKeyObject>;
  const priv = result.privateKey as InstanceType<typeof AsymmetricKeyObject>;

  const privDer = priv.export({ type: 'pkcs8', format: 'der' });
  const pubDer = pub.export({ type: 'spki', format: 'der' });

  const recreatedPriv = createPrivateKey({
    key: privDer,
    format: 'der',
    type: 'pkcs8',
  });
  const recreatedPub = createPublicKey({
    key: pubDer,
    format: 'der',
    type: 'spki',
  });

  expect(recreatedPriv.asymmetricKeyType).to.equal('x448');
  expect(recreatedPub.asymmetricKeyType).to.equal('x448');
});

// --- Async path tests ---

test(SUITE, 'generateKeyPair ed25519 async returns KeyObjects', async () => {
  const result = await new Promise<{
    publicKey: InstanceType<typeof AsymmetricKeyObject>;
    privateKey: InstanceType<typeof AsymmetricKeyObject>;
  }>((resolve, reject) => {
    generateKeyPair('ed25519', {}, (err, pubKey, privKey) => {
      if (err) reject(err);
      else
        resolve({
          publicKey: pubKey as InstanceType<typeof AsymmetricKeyObject>,
          privateKey: privKey as InstanceType<typeof AsymmetricKeyObject>,
        });
    });
  });

  expect(result.publicKey).to.be.an.instanceOf(KeyObject);
  expect(result.privateKey).to.be.an.instanceOf(KeyObject);
  expect(result.publicKey.type).to.equal('public');
  expect(result.privateKey.type).to.equal('private');
});

test(
  SUITE,
  'generateKeyPair ed25519 async with PEM encoding returns strings',
  async () => {
    const { publicKey, privateKey } = await new Promise<{
      publicKey: string;
      privateKey: string;
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
              publicKey: pubKey as string,
              privateKey: privKey as string,
            });
        },
      );
    });

    expect(typeof publicKey).to.equal('string');
    expect(typeof privateKey).to.equal('string');
    expect(publicKey).to.match(/^-----BEGIN PUBLIC KEY-----/);
    expect(privateKey).to.match(/^-----BEGIN PRIVATE KEY-----/);
  },
);
