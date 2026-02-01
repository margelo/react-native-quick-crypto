import {
  Buffer,
  generateKey,
  generateKeySync,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { test, assertThrowsAsync } from '../util';

const SUITE = 'keys.generateKey';

// --- generateKeySync AES Tests ---

test(SUITE, 'generateKeySync AES-128', () => {
  const key = generateKeySync('aes', { length: 128 });

  expect(key.type).to.equal('secret');
  const exported = key.export();
  expect(exported.length).to.equal(16);
});

test(SUITE, 'generateKeySync AES-192', () => {
  const key = generateKeySync('aes', { length: 192 });

  expect(key.type).to.equal('secret');
  const exported = key.export();
  expect(exported.length).to.equal(24);
});

test(SUITE, 'generateKeySync AES-256', () => {
  const key = generateKeySync('aes', { length: 256 });

  expect(key.type).to.equal('secret');
  const exported = key.export();
  expect(exported.length).to.equal(32);
});

test(SUITE, 'generateKeySync AES keys are unique', () => {
  const key1 = generateKeySync('aes', { length: 256 });
  const key2 = generateKeySync('aes', { length: 256 });

  const exported1 = key1.export();
  const exported2 = key2.export();

  expect(Buffer.compare(exported1, exported2)).to.not.equal(0);
});

// --- generateKeySync HMAC Tests ---

test(SUITE, 'generateKeySync HMAC 256-bit', () => {
  const key = generateKeySync('hmac', { length: 256 });

  expect(key.type).to.equal('secret');
  const exported = key.export();
  expect(exported.length).to.equal(32);
});

test(SUITE, 'generateKeySync HMAC 512-bit', () => {
  const key = generateKeySync('hmac', { length: 512 });

  expect(key.type).to.equal('secret');
  const exported = key.export();
  expect(exported.length).to.equal(64);
});

test(SUITE, 'generateKeySync HMAC minimum length (8 bits)', () => {
  const key = generateKeySync('hmac', { length: 8 });

  expect(key.type).to.equal('secret');
  const exported = key.export();
  expect(exported.length).to.equal(1);
});

test(SUITE, 'generateKeySync HMAC keys are unique', () => {
  const key1 = generateKeySync('hmac', { length: 256 });
  const key2 = generateKeySync('hmac', { length: 256 });

  const exported1 = key1.export();
  const exported2 = key2.export();

  expect(Buffer.compare(exported1, exported2)).to.not.equal(0);
});

// --- generateKey async AES Tests ---

test(SUITE, 'generateKey AES-128 async', async () => {
  const key = await new Promise<ReturnType<typeof generateKeySync>>(
    (resolve, reject) => {
      generateKey('aes', { length: 128 }, (err, k) => {
        if (err) reject(err);
        else resolve(k!);
      });
    },
  );

  expect(key.type).to.equal('secret');
  const exported = key.export();
  expect(exported.length).to.equal(16);
});

test(SUITE, 'generateKey AES-256 async', async () => {
  const key = await new Promise<ReturnType<typeof generateKeySync>>(
    (resolve, reject) => {
      generateKey('aes', { length: 256 }, (err, k) => {
        if (err) reject(err);
        else resolve(k!);
      });
    },
  );

  expect(key.type).to.equal('secret');
  const exported = key.export();
  expect(exported.length).to.equal(32);
});

// --- generateKey async HMAC Tests ---

test(SUITE, 'generateKey HMAC 256-bit async', async () => {
  const key = await new Promise<ReturnType<typeof generateKeySync>>(
    (resolve, reject) => {
      generateKey('hmac', { length: 256 }, (err, k) => {
        if (err) reject(err);
        else resolve(k!);
      });
    },
  );

  expect(key.type).to.equal('secret');
  const exported = key.export();
  expect(exported.length).to.equal(32);
});

test(SUITE, 'generateKey HMAC 512-bit async', async () => {
  const key = await new Promise<ReturnType<typeof generateKeySync>>(
    (resolve, reject) => {
      generateKey('hmac', { length: 512 }, (err, k) => {
        if (err) reject(err);
        else resolve(k!);
      });
    },
  );

  expect(key.type).to.equal('secret');
  const exported = key.export();
  expect(exported.length).to.equal(64);
});

// --- Error Cases ---

test(SUITE, 'generateKeySync throws for invalid AES length', async () => {
  await assertThrowsAsync(async () => {
    generateKeySync('aes', { length: 64 });
  }, 'must be 128, 192, or 256');
});

test(SUITE, 'generateKeySync throws for AES length 512', async () => {
  await assertThrowsAsync(async () => {
    generateKeySync('aes', { length: 512 });
  }, 'must be 128, 192, or 256');
});

test(SUITE, 'generateKeySync throws for HMAC length < 8', async () => {
  await assertThrowsAsync(async () => {
    generateKeySync('hmac', { length: 4 });
  }, 'must be >= 8');
});

test(SUITE, 'generateKeySync throws for invalid type', async () => {
  await assertThrowsAsync(async () => {
    // @ts-expect-error Testing invalid type
    generateKeySync('invalid', { length: 128 });
  }, "must be 'aes' or 'hmac'");
});

test(SUITE, 'generateKeySync throws for missing options', async () => {
  await assertThrowsAsync(async () => {
    // @ts-expect-error Testing missing options
    generateKeySync('aes');
  }, 'must be an object');
});

test(SUITE, 'generateKeySync throws for non-integer length', async () => {
  await assertThrowsAsync(async () => {
    generateKeySync('aes', { length: 128.5 });
  }, 'must be an integer');
});

test(SUITE, 'generateKey async passes error to callback', async () => {
  const error = await new Promise<Error>(resolve => {
    generateKey('aes', { length: 64 }, err => {
      resolve(err!);
    });
  });

  expect(error).to.be.instanceOf(Error);
  expect(error.message).to.include('must be 128, 192, or 256');
});

test(SUITE, 'generateKey throws for non-function callback', async () => {
  await assertThrowsAsync(async () => {
    // @ts-expect-error Testing invalid callback
    generateKey('aes', { length: 128 }, 'not a function');
  }, 'must be a function');
});
