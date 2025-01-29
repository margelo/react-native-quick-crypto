/**
 * Bun/Nodejs example of how to use hash
 * Should be used as a reference for how to implement hash in react-native-quick-crypto
 * Also used as a reference for @types/node/crypto.d.ts
 */

import { createHash } from 'node:crypto';

const payload = 'hello from bun';
const hash = createHash('sha256');
hash.update(payload);
const digest = hash.digest('hex');

console.log({ payload, digest });
