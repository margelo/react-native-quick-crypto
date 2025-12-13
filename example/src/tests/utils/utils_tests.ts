import { constants } from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';
import { Buffer } from '@craftzdog/react-native-buffer';
import crypto from 'react-native-quick-crypto';

const SUITE = 'utils';

// --- Constants Tests ---

test(SUITE, 'RSA_PKCS1_PADDING exists and is a number', () => {
  expect(typeof constants.RSA_PKCS1_PADDING).to.equal('number');
  expect(constants.RSA_PKCS1_PADDING).to.equal(1);
});

test(SUITE, 'RSA_PKCS1_OAEP_PADDING exists and is a number', () => {
  expect(typeof constants.RSA_PKCS1_OAEP_PADDING).to.equal('number');
  expect(constants.RSA_PKCS1_OAEP_PADDING).to.equal(4);
});

test(SUITE, 'RSA_NO_PADDING exists and is a number', () => {
  expect(typeof constants.RSA_NO_PADDING).to.equal('number');
  expect(constants.RSA_NO_PADDING).to.equal(3);
});

test(SUITE, 'RSA_PKCS1_PSS_PADDING exists and is a number', () => {
  expect(typeof constants.RSA_PKCS1_PSS_PADDING).to.equal('number');
  expect(constants.RSA_PKCS1_PSS_PADDING).to.equal(6);
});

test(SUITE, 'RSA_PSS_SALTLEN_DIGEST exists and is a number', () => {
  expect(typeof constants.RSA_PSS_SALTLEN_DIGEST).to.equal('number');
  expect(constants.RSA_PSS_SALTLEN_DIGEST).to.equal(-1);
});

test(SUITE, 'RSA_PSS_SALTLEN_MAX_SIGN exists and is a number', () => {
  expect(typeof constants.RSA_PSS_SALTLEN_MAX_SIGN).to.equal('number');
  expect(constants.RSA_PSS_SALTLEN_MAX_SIGN).to.equal(-2);
});

test(SUITE, 'RSA_PSS_SALTLEN_AUTO exists and is a number', () => {
  expect(typeof constants.RSA_PSS_SALTLEN_AUTO).to.equal('number');
  expect(constants.RSA_PSS_SALTLEN_AUTO).to.equal(-2);
});

test(SUITE, 'POINT_CONVERSION_COMPRESSED exists', () => {
  expect(typeof constants.POINT_CONVERSION_COMPRESSED).to.equal('number');
  expect(constants.POINT_CONVERSION_COMPRESSED).to.equal(2);
});

test(SUITE, 'POINT_CONVERSION_UNCOMPRESSED exists', () => {
  expect(typeof constants.POINT_CONVERSION_UNCOMPRESSED).to.equal('number');
  expect(constants.POINT_CONVERSION_UNCOMPRESSED).to.equal(4);
});

test(SUITE, 'POINT_CONVERSION_HYBRID exists', () => {
  expect(typeof constants.POINT_CONVERSION_HYBRID).to.equal('number');
  expect(constants.POINT_CONVERSION_HYBRID).to.equal(6);
});

test(SUITE, 'DH_CHECK_P_NOT_PRIME exists', () => {
  expect(typeof constants.DH_CHECK_P_NOT_PRIME).to.equal('number');
});

test(SUITE, 'DH_CHECK_P_NOT_SAFE_PRIME exists', () => {
  expect(typeof constants.DH_CHECK_P_NOT_SAFE_PRIME).to.equal('number');
});

test(SUITE, 'DH_NOT_SUITABLE_GENERATOR exists', () => {
  expect(typeof constants.DH_NOT_SUITABLE_GENERATOR).to.equal('number');
});

test(SUITE, 'DH_UNABLE_TO_CHECK_GENERATOR exists', () => {
  expect(typeof constants.DH_UNABLE_TO_CHECK_GENERATOR).to.equal('number');
});

test(SUITE, 'OPENSSL_VERSION_NUMBER exists', () => {
  expect(typeof constants.OPENSSL_VERSION_NUMBER).to.equal('number');
  expect(constants.OPENSSL_VERSION_NUMBER).to.be.greaterThan(0);
});

test(SUITE, 'All exported constants are numbers', () => {
  const allKeys = Object.keys(constants);
  expect(allKeys.length).to.be.greaterThan(0);

  for (const key of allKeys) {
    const value = constants[key as keyof typeof constants];
    expect(typeof value).to.equal('number');
  }
});

test(SUITE, 'RSA padding constants match Node.js values', () => {
  expect(constants.RSA_PKCS1_PADDING).to.equal(1);
  expect(constants.RSA_NO_PADDING).to.equal(3);
  expect(constants.RSA_PKCS1_OAEP_PADDING).to.equal(4);
  expect(constants.RSA_PKCS1_PSS_PADDING).to.equal(6);
});

test(SUITE, 'RSA PSS salt length constants match Node.js values', () => {
  expect(constants.RSA_PSS_SALTLEN_DIGEST).to.equal(-1);
  expect(constants.RSA_PSS_SALTLEN_MAX_SIGN).to.equal(-2);
  expect(constants.RSA_PSS_SALTLEN_AUTO).to.equal(-2);
});

test(SUITE, 'Point conversion constants match Node.js values', () => {
  expect(constants.POINT_CONVERSION_COMPRESSED).to.equal(2);
  expect(constants.POINT_CONVERSION_UNCOMPRESSED).to.equal(4);
  expect(constants.POINT_CONVERSION_HYBRID).to.equal(6);
});

// --- timingSafeEqual Tests ---

test(SUITE, 'timingSafeEqual should return true for equal buffers', () => {
  const a = Buffer.from('hello world');
  const b = Buffer.from('hello world');
  expect(crypto.timingSafeEqual(a, b)).to.equal(true);
});

test(SUITE, 'timingSafeEqual should return false for different buffers', () => {
  const a = Buffer.from('hello world');
  const b = Buffer.from('hello worlD');
  expect(crypto.timingSafeEqual(a, b)).to.equal(false);
});

test(SUITE, 'timingSafeEqual should work with Uint8Array', () => {
  const a = new Uint8Array([1, 2, 3, 4, 5]);
  const b = new Uint8Array([1, 2, 3, 4, 5]);
  expect(crypto.timingSafeEqual(a, b)).to.equal(true);
});

test(
  SUITE,
  'timingSafeEqual should return false for different Uint8Array',
  () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    const b = new Uint8Array([1, 2, 3, 4, 6]);
    expect(crypto.timingSafeEqual(a, b)).to.equal(false);
  },
);

test(SUITE, 'timingSafeEqual should work with ArrayBuffer', () => {
  const a = new Uint8Array([0xde, 0xad, 0xbe, 0xef]).buffer;
  const b = new Uint8Array([0xde, 0xad, 0xbe, 0xef]).buffer;
  expect(crypto.timingSafeEqual(a, b)).to.equal(true);
});

test(SUITE, 'timingSafeEqual should throw for different length buffers', () => {
  const a = Buffer.from('hello');
  const b = Buffer.from('hello world');
  expect(() => crypto.timingSafeEqual(a, b)).to.throw(RangeError);
});

test(SUITE, 'timingSafeEqual should work with empty buffers', () => {
  const a = Buffer.alloc(0);
  const b = Buffer.alloc(0);
  expect(crypto.timingSafeEqual(a, b)).to.equal(true);
});

test(SUITE, 'timingSafeEqual should work with single byte buffers', () => {
  const a = Buffer.from([0xff]);
  const b = Buffer.from([0xff]);
  expect(crypto.timingSafeEqual(a, b)).to.equal(true);

  const c = Buffer.from([0x00]);
  expect(crypto.timingSafeEqual(a, c)).to.equal(false);
});

test(SUITE, 'timingSafeEqual should work for HMAC comparison use case', () => {
  const hmac1 = crypto
    .createHmac('sha256', 'secret')
    .update('message')
    .digest();
  const hmac2 = crypto
    .createHmac('sha256', 'secret')
    .update('message')
    .digest();
  const hmac3 = crypto
    .createHmac('sha256', 'secret')
    .update('different')
    .digest();

  expect(crypto.timingSafeEqual(hmac1, hmac2)).to.equal(true);
  expect(crypto.timingSafeEqual(hmac1, hmac3)).to.equal(false);
});
