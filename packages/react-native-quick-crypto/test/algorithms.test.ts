import { normalizeAlgorithm } from '../src/Algorithms';

test('normalizeAlgorithm happy', () => {
  expect(normalizeAlgorithm('SHA-1', 'digest')).toEqual({
    name: 'SHA-1',
  });
  expect(normalizeAlgorithm({ name: 'SHA-1' }, 'digest')).toEqual({
    name: 'SHA-1',
  });
});

test('normalizeAlgorithm hashes', () => {
  expect(
    normalizeAlgorithm(
      {
        name: 'ECDSA',
        hash: 'SHA-256',
      },
      'sign',
    ),
  ).toEqual({
    name: 'ECDSA',
    hash: 'SHA-256',
  });
  expect(
    normalizeAlgorithm(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' },
      },
      'sign',
    ),
  ).toEqual({
    name: 'ECDSA',
    hash: {
      name: 'SHA-256',
    },
  });
});
