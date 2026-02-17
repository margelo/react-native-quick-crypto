// TODO: fix this test when we have a hashnames.ts file
//       i.e. after porting to nitro/new architecture
import { HashContext, normalizeHashName } from '../src/utils/hashnames';

test('normalizeHashName happy', () => {
  expect(normalizeHashName('SHA-1')).toBe('sha1');
  expect(normalizeHashName('SHA-256')).toBe('sha256');
  expect(normalizeHashName('SHA-384')).toBe('sha384');
  expect(normalizeHashName('SHA-512')).toBe('sha512');
});

test('normalizeHashName RSA-* legacy aliases', () => {
  expect(normalizeHashName('rsa-sha1')).toBe('sha1');
  expect(normalizeHashName('rsa-sha256')).toBe('sha256');
  expect(normalizeHashName('rsa-sha384')).toBe('sha384');
  expect(normalizeHashName('rsa-sha512')).toBe('sha512');
  expect(normalizeHashName('rsa-ripemd160')).toBe('ripemd160');
  expect(normalizeHashName('RSA-SHA256')).toBe('sha256');
});

test('normalizeHashName SHA-3 family', () => {
  expect(normalizeHashName('SHA3-256')).toBe('sha3-256');
  expect(normalizeHashName('SHA3-384')).toBe('sha3-384');
  expect(normalizeHashName('SHA3-512')).toBe('sha3-512');
  expect(normalizeHashName('sha3-256')).toBe('sha3-256');
  expect(normalizeHashName('sha3-384')).toBe('sha3-384');
  expect(normalizeHashName('sha3-512')).toBe('sha3-512');
});

test('normalizeHashName SHAKE/cSHAKE', () => {
  expect(normalizeHashName('shake128')).toBe('shake128');
  expect(normalizeHashName('shake256')).toBe('shake256');
  expect(normalizeHashName('cSHAKE128')).toBe('shake128');
  expect(normalizeHashName('cSHAKE256')).toBe('shake256');
});

test('normalizeHashName WebCrypto context SHA-3', () => {
  expect(normalizeHashName('sha3-256', HashContext.WebCrypto)).toBe('SHA3-256');
  expect(normalizeHashName('sha3-384', HashContext.WebCrypto)).toBe('SHA3-384');
  expect(normalizeHashName('sha3-512', HashContext.WebCrypto)).toBe('SHA3-512');
  expect(normalizeHashName('shake128', HashContext.WebCrypto)).toBe(
    'cSHAKE128',
  );
  expect(normalizeHashName('shake256', HashContext.WebCrypto)).toBe(
    'cSHAKE256',
  );
});

test('normalizeHashName sad', () => {
  expect(() => normalizeHashName('SHA-2')).toThrow('Invalid Hash Algorithm');
  expect(() => normalizeHashName('NOT-a-hash')).toThrow(
    'Invalid Hash Algorithm',
  );
});
