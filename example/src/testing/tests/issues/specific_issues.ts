import type { BinaryLikeNode } from '../../../../../src/Utils';
import { Buffer as CraftzdogBuffer } from '@craftzdog/react-native-buffer';
import { Buffer as FerossBuffer } from 'buffer';
import crypto from 'react-native-quick-crypto';
import { describe, it } from '../../MochaRNAdapter';
import { expect } from 'chai';

// -----------------------------------------------------------------------------
// tests

describe('specific issues', () => {

  it('issue 398', () => {
    const publicKeySpkiBase64 =
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENlFpbMBNfCY6Lhj9A/clefyxJVIXGJ0y6CcZ/cbbyyebvN6T0aNPvpQyFdUwRtYvFHlYbqIZOM8AoqdPcnSMIA==';

    const publicKey = getPublicKeyInPEMFormat(publicKeySpkiBase64);
    // console.log('\n' + publicKey);
    const encrypted = encrypt({
      payload: JSON.stringify({ a: 1 }),
      publicKey,
    });
    // console.log({ encrypted });
    const { response: decrypted } = decrypt({
      response: encrypted,
      secretKey: encrypted.secretKey,
    });
    expect(decrypted).to.equal({ a: 1 });
  });

  const largeKey = crypto.randomBytes(64);
  it('issue 505 - craftzdog buffer', () => {
    // an instance of CraftzdogBuffer
    testBufferConversion('test', largeKey);
  });
  it('issue 505 - feross buffer', () => {
    // not an instance of CraftzdogBuffer
    const largeKeyFeross = FerossBuffer.from(largeKey.toString('base64'), 'base64');
    testBufferConversion('test', largeKeyFeross);

  });
});


// -----------------------------------------------------------------------------
// #398
type EncryptRequest = {
  payload: string;
  publicKey: ArrayBuffer;
};
type EncryptResponse = {
  KEY: string;
  IV: string;
  PAYLOAD: string;
  secretKey: BinaryLikeNode;
};

const algo = 'aes-128-gcm';

const encrypt = ({ payload, publicKey }: EncryptRequest): EncryptResponse => {
  const secretKey = crypto.randomBytes(16);
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(algo, secretKey, iv);

  const encryptedPayload = FerossBuffer.concat([
    cipher.update(payload, 'utf8'),
    cipher.final(),
    cipher.getAuthTag(),
  ]).toString('base64');

  const encryptedSessionKey = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    },
    secretKey,
  );

  return {
    KEY: encryptedSessionKey.toString('base64'),
    IV: iv.toString('base64'),
    PAYLOAD: encryptedPayload,
    secretKey,
  };
};

const decrypt = ({
  response,
  secretKey,
}: {
  response: EncryptResponse;
  secretKey: BinaryLikeNode;
}) => {
  const { IV, PAYLOAD } = response;

  const decipher = crypto.createDecipheriv(
    algo,
    secretKey,
    FerossBuffer.from(IV, 'base64'),
  );

  const encryptedPayload = FerossBuffer.from(PAYLOAD, 'base64');
  let decrypted = decipher.update(
    FerossBuffer.from(encryptedPayload.subarray(0, encryptedPayload.length - 16)),
  );
  decrypted = FerossBuffer.concat([decrypted, decipher.final()]);

  return JSON.parse(decrypted.toString('utf8'));
};

const getPublicKeyInPEMFormat = (key: string): ArrayBuffer => {
  return crypto
    .createPublicKey({
      key: FerossBuffer.from(key, 'base64'),
      format: 'der',
      type: 'spki',
    })
    .export({
      type: 'spki',
      format: 'pem',
    });
};

// -----------------------------------------------------------------------------
// #505
const testBufferConversion = (clearText: string, largeKey: CraftzdogBuffer | FerossBuffer) => {
  const key = largeKey.subarray(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const enc = CraftzdogBuffer.concat([
    cipher.update(CraftzdogBuffer.from(clearText)) as unknown as CraftzdogBuffer,
    cipher.final() as unknown as CraftzdogBuffer,
  ]);
  const encB64 = enc.toString('base64');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const dec = CraftzdogBuffer.concat([
    decipher.update(CraftzdogBuffer.from(encB64, 'base64')) as unknown as CraftzdogBuffer,
    decipher.final() as unknown as CraftzdogBuffer,
  ]);
  expect(dec.toString()).to.equal(clearText);
};
