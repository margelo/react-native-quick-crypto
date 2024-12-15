/* eslint-disable @typescript-eslint/no-unused-expressions */
import { Ed, randomBytes, ab2str } from 'react-native-quick-crypto';
import { Buffer } from '@craftzdog/react-native-buffer';
// import type {
//   // KeyObject,
//   // CFRGKeyPairType,
//   // GenerateKeyPairCallback,
//   GenerateKeyPairOptions,
//   // KeyPairKey,
// } from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';

const SUITE = 'ed25519';

const encoder = new TextEncoder();
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const encode = (data: any): Uint8Array => encoder.encode(JSON.stringify(data));

/*
const jwkOptions: GenerateKeyPairOptions = {
  publicKeyEncoding: {
    format: 'jwk',
  },
  privateKeyEncoding: {
    format: 'jwk',
  },
};

const types: CFRGKeyPairType[] = ['ed25519', 'ed448', 'x25519', 'x448'];
types.map((type) => {
  test(SUITE, `generateKeyPair - ${type}`, () => {
    const callback: GenerateKeyPairCallback = (
      err: Error | undefined,
      publicKey: KeyPairKey,
      privateKey: KeyPairKey,
    ) => {
      expect(err).to.be.undefined;
      expect(publicKey).not.to.be.null;
      expect(privateKey).not.to.be.null;
      // console.log('publ', ab2str(publicKey as ArrayBuffer));
      // console.log('priv', ab2str(privateKey as ArrayBuffer));
    };

    crypto.generateKeyPair(
      type,
      jwkOptions,
      callback
    );
  });
});
*/

const data1 = Buffer.from('hello world');

test(SUITE, 'sign/verify - round trip happy', async () => {
  const ed = new Ed('ed25519', {});
  await ed.generateKeyPair();
  const signature = await ed.sign(data1.buffer);
  const verified = await ed.verify(signature, data1.buffer);
  expect(verified).to.be.true;
});

test(SUITE, 'sign/verify - round trip sad', async () => {
  const data2 = Buffer.from('goodbye cruel world');
  const ed = new Ed('ed25519', {});
  await ed.generateKeyPair();
  const signature = await ed.sign(data1.buffer);
  const verified = await ed.verify(signature, data2.buffer);
  expect(verified).to.be.false;
});

test(SUITE, 'sign/verify - bad signature does not verify', async () => {
  const ed = new Ed('ed25519', {});
  await ed.generateKeyPair();
  const signature = await ed.sign(data1.buffer);
  const signature2 = randomBytes(64).buffer;
  expect(ab2str(signature2)).not.to.equal(ab2str(signature));
  const verified = await ed.verify(signature2, data1.buffer);
  expect(verified).to.be.false;
});

test(SUITE, 'sign/verify - switched args does not verify', async () => {
  const ed = new Ed('ed25519', {});
  await ed.generateKeyPair();
  const signature = await ed.sign(data1.buffer);
  // verify(message, signature) is switched
  const verified = await ed.verify(data1.buffer, signature);
  expect(verified).to.be.false;
});

test(SUITE, 'sign/verify - non-internally generated private key', async () => {
  let ed1: Ed | null = new Ed('ed25519', {});
  await ed1.generateKeyPair();
  const priv = ed1.getPrivateKey();
  ed1 = null;

  const ed2 = new Ed('ed25519', {});
  const signature = await ed2.sign(data1.buffer, priv);
  const verified = await ed2.verify(signature, data1.buffer, priv);
  expect(verified).to.be.true;
});

test(
  SUITE,
  'sign/verify - bad non-internally generated private key',
  async () => {
    let ed1: Ed | null = new Ed('ed25519', {});
    await ed1.generateKeyPair();
    const priv = ed1.getPrivateKey();
    ed1 = null;

    const ed2 = new Ed('ed25519', {});
    const signature = await ed2.sign(data1.buffer, priv);
    const signature2 = randomBytes(64).buffer;
    expect(ab2str(signature2)).not.to.equal(ab2str(signature));
    const verified = await ed2.verify(signature2, data1.buffer, priv);
    expect(verified).to.be.false;
  },
);

test(SUITE, 'sign/verify - Uint8Arrays', () => {
  const data = { b: 'world', a: 'hello' };

  const ed1 = new Ed('ed25519', {});
  ed1.generateKeyPairSync();
  const priv = new Uint8Array(ed1.getPrivateKey());

  const ed2 = new Ed('ed25519', {});
  const signature = new Uint8Array(ed2.signSync(encode(data), priv));
  const verified = ed2.verifySync(signature, encode(data), priv);
  expect(verified).to.be.true;
});
