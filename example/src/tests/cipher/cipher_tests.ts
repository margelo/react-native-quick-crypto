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
const ciphers = getCiphers()
  .filter((c) => c.includes('CCM'))
  // .filter((c) => c.includes('CCM') || c.includes('OCB') || c.includes('SIV'))
;
// const ciphers = ['AES-128-GCM'];
const key = randomFillSync(new Uint8Array(32));
// CCM mode requires IV length between 7-13 bytes
// OCB mode requires IV length <= 15 bytes
const iv12 = randomFillSync(new Uint8Array(12));
// Other modes use 16 bytes
const iv16 = randomFillSync(new Uint8Array(16));
const aad = Buffer.from('0001020304050607', 'hex');
const plaintext =
  '32|RmVZZkFUVmpRRkp0TmJaUm56ZU9qcnJkaXNNWVNpTTU*|iXmckfRWZBGWWELw' +
  'eCBsThSsfUHLeRe0KCsK8ooHgxie0zOINpXxfZi/oNG7uq9JWFVCk70gfzQH8ZUJ' +
  'jAfaFg**';
const ciphertext = Buffer.from(plaintext, 'utf8');

// test(SUITE, 'valid algorithm', () => {
//   expect(() => {
//     createCipheriv('aes-128-cbc', key, iv, {});
//   }).to.not.throw();
// });

// test(SUITE, 'invalid algorithm', () => {
//   expect(() => {
//     createCipheriv('aes-128-boorad', key, iv, {});
//   }).to.throw(/Invalid Cipher Algorithm: aes-128-boorad/);
// });

// test(SUITE, 'getSupportedCiphers', () => {
//   expect(ciphers).to.be.instanceOf(Array);
//   expect(ciphers).to.have.length.greaterThan(0);
// });

// // different value types
// test(SUITE, 'strings', () => {
//   roundtrip('aes-128-cbc', '0123456789abcd0123456789', '12345678', plaintext);
// });

// test(SUITE, 'buffers', () => {
//   roundtrip(
//     'aes-128-cbc',
//     Buffer.from('0123456789abcd0123456789'),
//     Buffer.from('12345678'),
//     ciphertext,
//   );
// });

// update/final
ciphers.forEach(cipherName => {
  test(SUITE, `non-stream - ${cipherName}`, () => {
    // Use 12-byte IV for CCM mode, 16-byte for others
    const testIv = cipherName.includes('CCM') || cipherName.includes('OCB')
      ? iv12
      : iv16;
    roundtrip(cipherName, key, testIv, ciphertext);
  });
});

function roundtrip(
  cipherName: string,
  lKey: BinaryLikeNode,
  lIv: BinaryLike,
  payload: Buffer,
) {
  const cipher: Cipher = createCipheriv(cipherName, lKey, lIv, {});
  let ciph = cipher.update(payload, 'utf8', 'buffer') as Buffer;
  ciph = Buffer.concat([ciph, cipher.final()]);

  const decipher: Decipher = createDecipheriv(cipherName, lKey, lIv, {});
  if (
    cipherName.includes('CCM') ||
    cipherName.includes('OCB') ||
    cipherName.includes('SIV')
  ) {
    // For OCB and SIV modes, we need to get and set the auth tag
    const tag = cipher.getAuthTag();
    decipher.setAuthTag(tag);
  }

  let deciph = decipher.update(ciph, 'buffer', 'utf8');
  deciph += decipher.final('utf8') as string;
  // console.log('actual  ', deciph);
  // console.log('expected', plaintext);
  expect(deciph).to.equal(plaintext);
}
