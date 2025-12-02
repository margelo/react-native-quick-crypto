import { constants } from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test } from '../util';

const SUITE = 'constants';

// --- RSA Padding Constants ---

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

// --- RSA PSS Salt Length Constants ---

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

// --- Point Conversion Form Constants ---

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

// --- DH Constants ---

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

// --- Cipher Constants ---

test(SUITE, 'OPENSSL_VERSION_NUMBER exists', () => {
  expect(typeof constants.OPENSSL_VERSION_NUMBER).to.equal('number');
  expect(constants.OPENSSL_VERSION_NUMBER).to.be.greaterThan(0);
});

// --- All Constants Are Numbers ---

test(SUITE, 'All exported constants are numbers', () => {
  const allKeys = Object.keys(constants);
  expect(allKeys.length).to.be.greaterThan(0);

  for (const key of allKeys) {
    const value = constants[key as keyof typeof constants];
    expect(typeof value).to.equal('number');
  }
});

// --- Node.js Compatibility ---

test(SUITE, 'RSA padding constants match Node.js values', () => {
  // These values are defined by OpenSSL and should match Node.js
  expect(constants.RSA_PKCS1_PADDING).to.equal(1);
  expect(constants.RSA_NO_PADDING).to.equal(3);
  expect(constants.RSA_PKCS1_OAEP_PADDING).to.equal(4);
  expect(constants.RSA_PKCS1_PSS_PADDING).to.equal(6);
});

test(SUITE, 'RSA PSS salt length constants match Node.js values', () => {
  // These values are defined by OpenSSL and should match Node.js
  expect(constants.RSA_PSS_SALTLEN_DIGEST).to.equal(-1);
  expect(constants.RSA_PSS_SALTLEN_MAX_SIGN).to.equal(-2);
  expect(constants.RSA_PSS_SALTLEN_AUTO).to.equal(-2);
});

test(SUITE, 'Point conversion constants match Node.js values', () => {
  // These values are defined by OpenSSL EC_POINT conversion forms
  expect(constants.POINT_CONVERSION_COMPRESSED).to.equal(2);
  expect(constants.POINT_CONVERSION_UNCOMPRESSED).to.equal(4);
  expect(constants.POINT_CONVERSION_HYBRID).to.equal(6);
});
