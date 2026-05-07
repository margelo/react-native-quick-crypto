import {
  Buffer,
  createPrivateKey,
  createPublicKey,
  generateKeyPair,
  generateKeyPairSync,
  PrivateKeyObject,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';

const SUITE = 'keys.rawFormats';

type GenerateRawResult = {
  publicKey: ArrayBuffer | Buffer;
  privateKey: ArrayBuffer | Buffer;
};

function generateKeyPairAsync(
  type: 'ec' | 'ed25519' | 'ed448' | 'x25519' | 'x448',
  options: object,
): Promise<GenerateRawResult> {
  return new Promise((resolve, reject) => {
    generateKeyPair(type, options, (err, publicKey, privateKey) => {
      if (err) reject(err);
      else
        resolve({
          publicKey: publicKey as ArrayBuffer | Buffer,
          privateKey: privateKey as ArrayBuffer | Buffer,
        });
    });
  });
}

// --- KeyObject.export with raw formats ---

test(SUITE, 'PublicKeyObject.export raw-public for X25519', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const rawPub = publicKey.export({ format: 'raw-public' });
  const rawPriv = privateKey.export({ format: 'raw-private' });
  expect(rawPub).to.be.instanceOf(Buffer);
  expect(rawPriv).to.be.instanceOf(Buffer);
  expect(rawPub.length).to.equal(32);
  expect(rawPriv.length).to.equal(32);
});

test(SUITE, 'PublicKeyObject.export raw-public for Ed25519', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'raw-public' });
  const rawPriv = privateKey.export({ format: 'raw-private' });
  expect(rawPub.length).to.equal(32);
  expect(rawPriv.length).to.equal(32);
});

test(SUITE, 'PublicKeyObject.export raw-public for EC P-256', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });
  const uncompressed = publicKey.export({ format: 'raw-public' });
  expect(uncompressed.length).to.equal(65);
  expect(uncompressed[0]).to.equal(0x04);

  const compressed = publicKey.export({
    format: 'raw-public',
    type: 'compressed',
  });
  expect(compressed.length).to.equal(33);
  expect(compressed[0] === 0x02 || compressed[0] === 0x03).to.equal(true);

  const rawPriv = privateKey.export({ format: 'raw-private' });
  expect(rawPriv.length).to.equal(32);
});

test(SUITE, 'PrivateKeyObject.export raw-seed for ML-DSA-44', async () => {
  // ML-DSA may not be supported on all OpenSSL builds — guard.
  let privateKey: PrivateKeyObject;
  try {
    ({ privateKey } = generateKeyPairSync('ml-dsa-44'));
  } catch {
    return; // skip if not supported
  }
  if (!(privateKey instanceof PrivateKeyObject)) return;
  const seed = privateKey.export({ format: 'raw-seed' });
  expect(seed).to.be.instanceOf(Buffer);
  expect(seed.length).to.be.greaterThan(0);
});

// --- createPublicKey / createPrivateKey with raw formats ---

test(SUITE, 'createPublicKey raw-public for X25519', async () => {
  const { publicKey } = await generateKeyPairAsync('x25519', {
    publicKeyEncoding: { format: 'raw-public' },
    privateKeyEncoding: { format: 'raw-private' },
  });

  const pub = createPublicKey({
    key: publicKey as Buffer,
    format: 'raw-public',
    asymmetricKeyType: 'x25519',
  });
  expect(pub.type).to.equal('public');
  expect(pub.asymmetricKeyType).to.equal('x25519');

  const reExported = pub.export({ format: 'raw-public' });
  expect(Buffer.compare(reExported, publicKey as Buffer)).to.equal(0);
});

test(SUITE, 'createPrivateKey raw-private for Ed25519', async () => {
  const { privateKey } = await generateKeyPairAsync('ed25519', {
    publicKeyEncoding: { format: 'raw-public' },
    privateKeyEncoding: { format: 'raw-private' },
  });

  const priv = createPrivateKey({
    key: privateKey as Buffer,
    format: 'raw-private',
    asymmetricKeyType: 'ed25519',
  });
  expect(priv.type).to.equal('private');
  expect(priv.asymmetricKeyType).to.equal('ed25519');

  const reExported = priv.export({ format: 'raw-private' });
  expect(Buffer.compare(reExported, privateKey as Buffer)).to.equal(0);
});

test(SUITE, 'createPublicKey raw-public EC P-256 round-trip', async () => {
  const { publicKey } = await generateKeyPairAsync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { format: 'raw-public' },
    privateKeyEncoding: { format: 'raw-private' },
  });

  const pub = createPublicKey({
    key: publicKey as Buffer,
    format: 'raw-public',
    asymmetricKeyType: 'ec',
    namedCurve: 'P-256',
  });
  expect(pub.type).to.equal('public');
  expect(pub.asymmetricKeyType).to.equal('ec');

  const reExported = pub.export({ format: 'raw-public' });
  expect(Buffer.compare(reExported, publicKey as Buffer)).to.equal(0);
});

test(SUITE, 'createPrivateKey raw-private EC P-256 round-trip', async () => {
  const { privateKey } = await generateKeyPairAsync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { format: 'raw-public' },
    privateKeyEncoding: { format: 'raw-private' },
  });

  const priv = createPrivateKey({
    key: privateKey as Buffer,
    format: 'raw-private',
    asymmetricKeyType: 'ec',
    namedCurve: 'P-256',
  });
  expect(priv.type).to.equal('private');
  expect(priv.asymmetricKeyType).to.equal('ec');

  const reExported = priv.export({ format: 'raw-private' });
  expect(Buffer.compare(reExported, privateKey as Buffer)).to.equal(0);
});

// --- generateKeyPair raw output ---

test(SUITE, 'generateKeyPairSync x25519 with raw-public output', () => {
  const { publicKey, privateKey } = generateKeyPairSync('x25519', {
    publicKeyEncoding: { format: 'raw-public' },
    privateKeyEncoding: { format: 'raw-private' },
  });
  expect(Buffer.from(publicKey as ArrayBuffer).length).to.equal(32);
  expect(Buffer.from(privateKey as ArrayBuffer).length).to.equal(32);
});

test(SUITE, 'generateKeyPair ec compressed raw-public', async () => {
  const { publicKey } = await generateKeyPairAsync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { format: 'raw-public', type: 'compressed' },
    privateKeyEncoding: { format: 'raw-private' },
  });
  const buf = Buffer.from(publicKey as ArrayBuffer);
  expect(buf.length).to.equal(33);
  expect(buf[0] === 0x02 || buf[0] === 0x03).to.equal(true);
});
