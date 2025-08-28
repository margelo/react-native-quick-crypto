/* eslint-disable @typescript-eslint/no-unused-expressions */
import { Buffer } from '@craftzdog/react-native-buffer';
import { expect } from 'chai';
import { ab2str, Ed, randomBytes } from 'react-native-quick-crypto';
import { test } from '../util';

const SUITE = 'cfrg';

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

test(SUITE, 'ed25519 - sign/verify - round trip happy', async () => {
  const ed = new Ed('ed25519', {});
  await ed.generateKeyPair();
  const signature = await ed.sign(data1.buffer);
  const verified = await ed.verify(signature, data1.buffer);
  expect(verified).to.be.true;
});

test(SUITE, 'ed25519 - sign/verify - round trip sad', async () => {
  const data2 = Buffer.from('goodbye cruel world');
  const ed = new Ed('ed25519', {});
  await ed.generateKeyPair();
  const signature = await ed.sign(data1.buffer);
  const verified = await ed.verify(signature, data2.buffer);
  expect(verified).to.be.false;
});

test(
  SUITE,
  'ed25519 - sign/verify - bad signature does not verify',
  async () => {
    const ed = new Ed('ed25519', {});
    await ed.generateKeyPair();
    const signature = await ed.sign(data1.buffer);
    const signature2 = randomBytes(64).buffer;
    expect(ab2str(signature2)).not.to.equal(ab2str(signature));
    const verified = await ed.verify(signature2, data1.buffer);
    expect(verified).to.be.false;
  },
);

test(
  SUITE,
  'ed25519 - sign/verify - switched args does not verify',
  async () => {
    const ed = new Ed('ed25519', {});
    await ed.generateKeyPair();
    const signature = await ed.sign(data1.buffer);
    // verify(message, signature) is switched
    const verified = await ed.verify(data1.buffer, signature);
    expect(verified).to.be.false;
  },
);

test(
  SUITE,
  'ed25519 - sign/verify - non-internally generated private key',
  async () => {
    const pub = Buffer.from(
      'e106bf015ad54a64022295c7af2c35f9511eb37264a7722a9642eaac6c59a494',
      'hex',
    );
    const priv = Buffer.from(
      '5f27e170afc5091c4933d980c5fe86af997b91375115c6ee2c0fe4ea12400ed0',
      'hex',
    );

    const ed2 = new Ed('ed25519', {});
    const signature = await ed2.sign(data1.buffer, priv);
    const verified = await ed2.verify(signature, data1.buffer, pub);
    expect(verified).to.be.true;
  },
);

test(SUITE, 'ed25519 - sign/verify - bad signature', async () => {
  let ed1: Ed | null = new Ed('ed25519', {});
  await ed1.generateKeyPair();
  const pub = ed1.getPublicKey();
  const priv = ed1.getPrivateKey();
  ed1 = null;

  const ed2 = new Ed('ed25519', {});
  const signature = await ed2.sign(data1.buffer, priv);
  const signature2 = randomBytes(64).buffer;
  expect(ab2str(signature2)).not.to.equal(ab2str(signature));
  const verified = await ed2.verify(signature2, data1.buffer, pub);
  expect(verified).to.be.false;
});

test(
  SUITE,
  'ed25519 - sign/verify - bad verify with private key, not public',
  async () => {
    let ed1: Ed | null = new Ed('ed25519', {});
    await ed1.generateKeyPair();
    const priv = ed1.getPrivateKey();
    ed1 = null;

    const ed2 = new Ed('ed25519', {});
    const signature = await ed2.sign(data1.buffer, priv);
    const verified = await ed2.verify(signature, data1.buffer, priv);
    expect(verified).to.be.false;
  },
);

test(SUITE, 'ed25519 - sign/verify - Uint8Arrays', () => {
  const data = { b: 'world', a: 'hello' };

  const ed1 = new Ed('ed25519', {});
  ed1.generateKeyPairSync();
  const pub = new Uint8Array(ed1.getPublicKey());
  const priv = new Uint8Array(ed1.getPrivateKey());

  const ed2 = new Ed('ed25519', {});
  const signature = new Uint8Array(ed2.signSync(encode(data), priv));
  const verified = ed2.verifySync(signature, encode(data), pub);
  expect(verified).to.be.true;
});
