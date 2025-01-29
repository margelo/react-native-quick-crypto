import { Buffer } from '@craftzdog/react-native-buffer';
import {
  getCiphers,
  createCipheriv,
  createDecipheriv,
  randomFillSync,
  type BinaryLikeNode,
  type BinaryLike,
  type Cipher,
  type Decipher,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';

const SUITE = 'cipher';
const ciphers = getCiphers();
const key = randomFillSync(new Uint8Array(32));
const iv = randomFillSync(new Uint8Array(16));
const plaintext =
  '32|RmVZZkFUVmpRRkp0TmJaUm56ZU9qcnJkaXNNWVNpTTU*|iXmckfRWZBGWWELw' +
  'eCBsThSsfUHLeRe0KCsK8ooHgxie0zOINpXxfZi/oNG7uq9JWFVCk70gfzQH8ZUJ' +
  'jAfaFg**';

test(SUITE, 'valid algorithm', () => {
  expect(() => {
    createCipheriv('aes-128-cbc', key, iv, {});
  }).to.not.throw();
});

test(SUITE, 'invalid algorithm', () => {
  expect(() => {
    createCipheriv('aes-128-boorad', key, iv, {});
  }).to.throw(/Invalid Cipher Algorithm: aes-128-boorad/);
});

test(SUITE, 'getSupportedCiphers', () => {
  expect(ciphers).to.be.instanceOf(Array);
  expect(ciphers).to.have.length.greaterThan(0);
});

// different value types
test(SUITE, 'strings', () => {
  roundtrip('aes-128-cbc', '0123456789abcd0123456789', '12345678', plaintext);
});

test(SUITE, 'buffers', () => {
  roundtrip(
    'aes-128-cbc',
    Buffer.from('0123456789abcd0123456789'),
    Buffer.from('12345678'),
    plaintext,
  );
});

// update/final
ciphers.forEach(cipherName => {
  test(SUITE, `non-stream - ${cipherName}`, () => {
    roundtrip(cipherName, key, iv, plaintext);
  });
});

function roundtrip(
  cipherName: string,
  lKey: BinaryLikeNode,
  lIv: BinaryLike,
  payload: string,
) {
  const cipher: Cipher = createCipheriv(cipherName, lKey, lIv, {});
  let ciph = cipher.update(payload, 'utf8', 'buffer') as Buffer;
  ciph = Buffer.concat([ciph, cipher.final()]);

  const decipher: Decipher = createDecipheriv(cipherName, lKey, lIv, {});
  let deciph = decipher.update(ciph, 'buffer', 'utf8');
  deciph += decipher.final('utf8') as string;
  expect(deciph).to.equal(plaintext);
}
