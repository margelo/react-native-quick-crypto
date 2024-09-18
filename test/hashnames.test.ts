import { HashContext, normalizeHashName } from '../src/Hashnames';

test('normalizeHashName happy', () => {
  expect(normalizeHashName('SHA-1')).toBe('sha1');
  expect(normalizeHashName('SHA-256')).toBe('sha256');
  expect(normalizeHashName('SHA-384')).toBe('sha384');
  expect(normalizeHashName('SHA-512')).toBe('sha512');
  expect(normalizeHashName({name:'SHA-256'})).toBe('sha256');
});

test('normalizeHashName sad', () => {
  expect(normalizeHashName('SHA-2')).toBe('sha-2');
  expect(normalizeHashName('NOT-a-hash', HashContext.JwkRsaPss)).toBe(
    'not-a-hash',
  );
});
