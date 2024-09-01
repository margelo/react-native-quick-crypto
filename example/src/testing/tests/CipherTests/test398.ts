import type { BinaryLikeNode } from './../../../../../src/Utils';
import { Buffer } from 'buffer';
// import { Buffer } from '@craftzdog/react-native-buffer';
import crypto from 'react-native-quick-crypto';
import { describe, it } from '../../MochaRNAdapter';
import { expect } from 'chai';

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

  const encryptedPayload = Buffer.concat([
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
    Buffer.from(IV, 'base64'),
  );

  const encryptedPayload = Buffer.from(PAYLOAD, 'base64');
  let decrypted = decipher.update(
    Buffer.from(encryptedPayload.subarray(0, encryptedPayload.length - 16)),
  );
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return JSON.parse(decrypted.toString('utf8'));
};

const getPublicKeyInPEMFormat = (key: string): ArrayBuffer => {
  return crypto
    .createPublicKey({
      key: Buffer.from(key, 'base64'),
      format: 'der',
      type: 'spki',
    })
    .export({
      type: 'spki',
      format: 'pem',
    });
};

describe('test398', () => {
  it('test398', () => {
    const publicKeySpkiBase64 =
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENlFpbMBNfCY6Lhj9A/clefyxJVIXGJ0y6CcZ/cbbyyebvN6T0aNPvpQyFdUwRtYvFHlYbqIZOM8AoqdPcnSMIA==';

    const publicKey = getPublicKeyInPEMFormat(publicKeySpkiBase64);
    console.log('\n' + publicKey);
    const encrypted = encrypt({
      payload: JSON.stringify({ a: 1 }),
      publicKey,
    });
    console.log({ encrypted });
    const { response: decrypted } = decrypt({
      response: encrypted,
      secretKey: encrypted.secretKey,
    });
    expect(decrypted).to.equal({ a: 1 });
  });
});
