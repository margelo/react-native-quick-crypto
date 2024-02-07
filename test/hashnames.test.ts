import { HashContext, normalizeHashName } from '../src/Hashnames';

test('normalizeHashName happy', () => {
  expect(normalizeHashName('SHA-1')).toBe('sha1');
  expect(normalizeHashName('RSA-OAEP-512', HashContext.JwkRsaPss)).toBe(
    'PS512'
  );
});

test('normalizeHashName sad', () => {
  expect(normalizeHashName('SHA-2')).toBe('sha-2');
  expect(normalizeHashName('NOT-a-hash', HashContext.JwkRsaPss)).toBe(
    'not-a-hash'
  );
});
