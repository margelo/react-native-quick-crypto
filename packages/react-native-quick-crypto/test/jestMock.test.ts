// `virtual` because the package can't resolve its own name inside this repo;
// apps use the same call without it.
jest.mock('react-native-quick-crypto', () => jest.requireActual('../jest'), {
  virtual: true,
});

import QuickCrypto, {
  CryptoKey,
  createCipheriv,
  createDecipheriv,
  createHash,
  install,
  randomBytes,
} from 'react-native-quick-crypto';

test('jest mock exposes the default export and named exports', () => {
  expect(typeof QuickCrypto.createHash).toBe('function');
  expect(QuickCrypto.createHash).toBe(createHash);
  expect(typeof QuickCrypto.Buffer.from).toBe('function');
  expect(() => install()).not.toThrow();
});

test('jest mock hashes with real results', () => {
  expect(createHash('sha256').update('abc').digest('hex')).toBe(
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  );
});

test('jest mock round-trips AES-256-GCM', () => {
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([
    cipher.update('secret', 'utf8'),
    cipher.final(),
  ]);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(cipher.getAuthTag());
  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  expect(plaintext.toString('utf8')).toBe('secret');
});

test('jest mock subtle.verify resolves to a boolean', async () => {
  const key = await QuickCrypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
  expect(key).toBeInstanceOf(CryptoKey);
  const data = new TextEncoder().encode('hello');
  const signature = await QuickCrypto.subtle.sign('HMAC', key, data);
  await expect(
    QuickCrypto.subtle.verify('HMAC', key, signature, data),
  ).resolves.toBe(true);
});
