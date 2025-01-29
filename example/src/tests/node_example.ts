/**
 * NodeJS example of how to use crypto
 * Should be used as a reference for how to implement crypto in react-native-quick-crypto
 * Also used as a reference for @types/node/crypto.d.ts
 *
 * Run with `bun run example/src/tests/node_example.ts`
 */

import { createHash, createCipheriv } from 'node:crypto';
import type { BinaryToTextEncoding, Encoding } from 'node:crypto';

const payload = 'Test123';

const encoding: BinaryToTextEncoding = 'hex';
const inputEncoding: Encoding = 'utf8';
const outputEncoding: Encoding = 'hex';

/**
 * Hash
 */
const hash = createHash('sha256');
hash.update(payload);
const digest = hash.digest(encoding);
console.log('hash', { payload, encoding, digest });

/**
 * Cipher
 */
const key = new Uint8Array(Buffer.from('0123456789abcdef'));
const iv = new Uint8Array(Buffer.from('0123456789abcdef'));
const cipher = createCipheriv('aes-128-cbc', key, iv);
let encrypted = cipher.update(payload, inputEncoding, outputEncoding);
encrypted += cipher.final(outputEncoding);
console.log('cipher', { payload, inputEncoding, outputEncoding, encrypted });
