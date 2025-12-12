import { Buffer } from '@craftzdog/react-native-buffer';
import { expect } from 'chai';
import { test } from '../util';

import crypto from 'react-native-quick-crypto';

const SUITE = 'timingSafeEqual';

test(SUITE, 'should return true for equal buffers', () => {
  const a = Buffer.from('hello world');
  const b = Buffer.from('hello world');
  expect(crypto.timingSafeEqual(a, b)).to.equal(true);
});

test(SUITE, 'should return false for different buffers', () => {
  const a = Buffer.from('hello world');
  const b = Buffer.from('hello worlD');
  expect(crypto.timingSafeEqual(a, b)).to.equal(false);
});

test(SUITE, 'should work with Uint8Array', () => {
  const a = new Uint8Array([1, 2, 3, 4, 5]);
  const b = new Uint8Array([1, 2, 3, 4, 5]);
  expect(crypto.timingSafeEqual(a, b)).to.equal(true);
});

test(SUITE, 'should return false for different Uint8Array', () => {
  const a = new Uint8Array([1, 2, 3, 4, 5]);
  const b = new Uint8Array([1, 2, 3, 4, 6]);
  expect(crypto.timingSafeEqual(a, b)).to.equal(false);
});

test(SUITE, 'should work with ArrayBuffer', () => {
  const a = new Uint8Array([0xde, 0xad, 0xbe, 0xef]).buffer;
  const b = new Uint8Array([0xde, 0xad, 0xbe, 0xef]).buffer;
  expect(crypto.timingSafeEqual(a, b)).to.equal(true);
});

test(SUITE, 'should throw for different length buffers', () => {
  const a = Buffer.from('hello');
  const b = Buffer.from('hello world');
  expect(() => crypto.timingSafeEqual(a, b)).to.throw(RangeError);
});

test(SUITE, 'should work with empty buffers', () => {
  const a = Buffer.alloc(0);
  const b = Buffer.alloc(0);
  expect(crypto.timingSafeEqual(a, b)).to.equal(true);
});

test(SUITE, 'should work with single byte buffers', () => {
  const a = Buffer.from([0xff]);
  const b = Buffer.from([0xff]);
  expect(crypto.timingSafeEqual(a, b)).to.equal(true);

  const c = Buffer.from([0x00]);
  expect(crypto.timingSafeEqual(a, c)).to.equal(false);
});

test(SUITE, 'should work for HMAC comparison use case', () => {
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
