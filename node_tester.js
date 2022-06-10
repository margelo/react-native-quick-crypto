const crypto = require('crypto');

const cipher = crypto.createCipher('aes192', 'MySecretKey123');

const plaintext = 'Keep this a secret? No! Tell everyone about fast-crypto!';
// Encrypt plaintext which is in utf8 format
// to a ciphertext which will be in hex
let ciph = cipher.update(plaintext, 'utf8', 'hex');
// Only use binary or hex, not base64.
ciph += cipher.final('hex');

console.warn('generated ciph', ciph);
