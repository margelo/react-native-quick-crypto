/* eslint-disable @typescript-eslint/no-unused-expressions */
import { Ed, randomBytes, ab2str } from 'react-native-quick-crypto';
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

test(SUITE, 'sign/verify - round trip happy', async () => {
  const data = Buffer.from('hello world');
  const ed = new Ed('ed25519', {});
  await ed.generateKeyPair();
  const signature = await ed.sign(data.buffer);
  const verified = await ed.verify(signature, data.buffer);
  expect(verified).to.be.true;
});

test(SUITE, 'sign/verify - round trip sad', async () => {
  const data1 = Buffer.from('hello world');
  const data2 = Buffer.from('goodbye cruel world');
  const ed = new Ed('ed25519', {});
  await ed.generateKeyPair();
  const signature = await ed.sign(data1.buffer);
  const verified = await ed.verify(signature, data2.buffer);
  expect(verified).to.be.false;
});

test(SUITE, 'sign/verify - bad signature does not verify', async () => {
  const data = Buffer.from('hello world');
  const ed = new Ed('ed25519', {});
  await ed.generateKeyPair();
  const signature = await ed.sign(data.buffer);
  const signature2 = randomBytes(64).buffer;
  expect(ab2str(signature2)).not.to.equal(ab2str(signature));
  const verified = await ed.verify(signature2, data.buffer);
  expect(verified).to.be.false;
});
