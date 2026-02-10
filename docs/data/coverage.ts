/**
 * This file tracks the implementation status of react-native-quick-crypto against the standard Node.js crypto API and the W3C WebCrypto API.
 */

export type CapabilityStatus =
  | 'implemented'
  | 'missing'
  | 'partial'
  | 'not-in-node';

export interface CoverageItem {
  name: string;
  status?: CapabilityStatus;
  note?: string;
  subItems?: CoverageItem[];
}

export interface CoverageCategory {
  title: string;
  description?: string;
  items: CoverageItem[];
}

export const COVERAGE_DATA: CoverageCategory[] = [
  {
    title: 'Post-Quantum Cryptography (PQC)',
    description: 'Quantum-resistant cryptography algorithms (FIPS 203/204).',
    items: [
      {
        name: 'ML-DSA (Digital Signatures)',
        status: 'implemented',
        note: 'ML-DSA-44, 65, 87',
      },
      {
        name: 'ML-KEM (Key Encapsulation)',
        status: 'implemented',
        note: 'ML-KEM-512, 768, 1024',
      },
    ],
  },
  {
    title: 'Crypto Classes',
    items: [
      {
        name: 'Certificate',
        subItems: [
          { name: 'exportChallenge', status: 'missing' },
          { name: 'exportPublicKey', status: 'missing' },
          { name: 'verifySpkac', status: 'missing' },
        ],
      },
      {
        name: 'Cipheriv',
        subItems: [
          { name: 'final', status: 'implemented' },
          { name: 'getAuthTag', status: 'implemented' },
          { name: 'setAAD', status: 'implemented' },
          { name: 'setAutoPadding', status: 'implemented' },
          { name: 'update', status: 'implemented' },
        ],
      },
      {
        name: 'Decipheriv',
        subItems: [
          { name: 'final', status: 'implemented' },
          { name: 'setAAD', status: 'implemented' },
          { name: 'setAuthTag', status: 'implemented' },
          { name: 'setAutoPadding', status: 'implemented' },
          { name: 'update', status: 'implemented' },
        ],
      },
      {
        name: 'DiffieHellman',
        status: 'implemented',
        note: 'Use crypto.generateKeys or crypto.diffieHellman instead',
      },
      {
        name: 'ECDH',
        status: 'implemented',
        note: 'Use simple ECDH methods instead',
      },
      {
        name: 'Hash',
        subItems: [
          { name: 'copy', status: 'implemented' },
          { name: 'digest', status: 'implemented' },
          { name: 'update', status: 'implemented' },
        ],
      },
      {
        name: 'Hmac',
        subItems: [
          { name: 'digest', status: 'implemented' },
          { name: 'update', status: 'implemented' },
        ],
      },
      {
        name: 'Sign',
        subItems: [
          { name: 'sign', status: 'implemented' },
          { name: 'update', status: 'implemented' },
        ],
      },
      {
        name: 'Verify',
        subItems: [
          { name: 'verify', status: 'implemented' },
          { name: 'update', status: 'implemented' },
        ],
      },
      {
        name: 'KeyObject',
        subItems: [
          { name: 'asymmetricKeyType', status: 'implemented' },
          { name: 'export', status: 'implemented' },
          { name: 'type', status: 'implemented' },
          { name: 'asymmetricKeyDetails', status: 'missing' },
          { name: 'equals', status: 'missing' },
          { name: 'symmetricKeySize', status: 'missing' },
          { name: 'toCryptoKey', status: 'missing' },
          { name: 'from', status: 'missing', note: 'static' },
        ],
      },
      {
        name: 'X509Certificate',
        status: 'missing',
      },
    ],
  },
  {
    title: 'Crypto Methods',
    items: [
      { name: 'argon2', status: 'missing' },
      { name: 'checkPrime', status: 'missing' },
      { name: 'constants', status: 'implemented' },
      { name: 'createCipheriv', status: 'implemented' },
      { name: 'createDecipheriv', status: 'implemented' },
      { name: 'createDiffieHellman', status: 'implemented' },
      { name: 'createDiffieHellmanGroup', status: 'implemented' },
      { name: 'createECDH', status: 'implemented' },
      { name: 'createHash', status: 'implemented' },
      { name: 'createHmac', status: 'implemented' },
      { name: 'createPrivateKey', status: 'implemented' },
      { name: 'createPublicKey', status: 'implemented' },
      { name: 'createSecretKey', status: 'implemented' },
      { name: 'createSign', status: 'implemented' },
      { name: 'createVerify', status: 'implemented' },
      { name: 'decapsulate', status: 'missing' },
      { name: 'sign', status: 'implemented', note: 'One-shot signing' },
      { name: 'verify', status: 'implemented', note: 'One-shot verification' },
      {
        name: 'diffieHellman',
        subItems: [
          { name: 'dh', status: 'implemented' },
          { name: 'ec', status: 'implemented' },
          { name: 'x448', status: 'implemented' },
          { name: 'x25519', status: 'implemented' },
        ],
      },
      { name: 'encapsulate', status: 'missing' },
      { name: 'fips', status: 'missing' },
      {
        name: 'generateKey',
        subItems: [
          { name: 'aes', status: 'implemented' },
          { name: 'hmac', status: 'implemented' },
        ],
      },
      {
        name: 'generateKeyPair',
        subItems: [
          { name: 'rsa', status: 'implemented' },
          { name: 'rsa-pss', status: 'implemented' },
          { name: 'dsa', status: 'missing' },
          { name: 'ec', status: 'implemented' },
          { name: 'ed25519', status: 'implemented' },
          { name: 'ed448', status: 'implemented' },
          { name: 'x25519', status: 'implemented' },
          { name: 'x448', status: 'implemented' },
          { name: 'dh', status: 'missing' },
        ],
      },
      {
        name: 'generateKeyPairSync',
        subItems: [
          { name: 'rsa', status: 'implemented' },
          { name: 'rsa-pss', status: 'implemented' },
          { name: 'dsa', status: 'missing' },
          { name: 'ec', status: 'implemented' },
          { name: 'ed25519', status: 'implemented' },
          { name: 'ed448', status: 'implemented' },
          { name: 'x25519', status: 'implemented' },
          { name: 'x448', status: 'implemented' },
          { name: 'dh', status: 'missing' },
        ],
      },
      {
        name: 'generateKeySync',
        subItems: [
          { name: 'aes', status: 'implemented' },
          { name: 'hmac', status: 'implemented' },
        ],
      },
      { name: 'generatePrime', status: 'missing' },
      { name: 'getCipherInfo', status: 'missing' },
      { name: 'getCiphers', status: 'implemented' },
      { name: 'getCurves', status: 'missing' },
      { name: 'getDiffieHellman', status: 'implemented' },
      { name: 'getFips', status: 'missing' },
      { name: 'getHashes', status: 'implemented' },
      { name: 'getRandomValues', status: 'implemented' },
      { name: 'hash', status: 'missing' },
      { name: 'hkdf', status: 'implemented' },
      { name: 'pbkdf2', status: 'implemented' },
      { name: 'privateDecrypt / privateEncrypt', status: 'implemented' },
      { name: 'publicDecrypt / publicEncrypt', status: 'implemented' },
      { name: 'randomBytes', status: 'implemented' },
      { name: 'randomFill / randomFillSync', status: 'implemented' },
      { name: 'randomInt', status: 'implemented' },
      { name: 'randomUUID', status: 'implemented' },
      { name: 'scrypt', status: 'implemented' },
      { name: 'secureHeapUsed', status: 'missing' },
      { name: 'setEngine', status: 'missing' },
      { name: 'setFips', status: 'missing' },
      {
        name: 'sign',
        subItems: [
          { name: 'RSASSA-PKCS1-v1_5', status: 'implemented' },
          { name: 'RSA-PSS', status: 'implemented' },
          { name: 'ECDSA', status: 'implemented' },
          { name: 'Ed25519', status: 'implemented' },
          { name: 'Ed448', status: 'implemented' },
          { name: 'HMAC', status: 'implemented' },
        ],
      },
      {
        name: 'verify',
        subItems: [
          { name: 'RSASSA-PKCS1-v1_5', status: 'implemented' },
          { name: 'RSA-PSS', status: 'implemented' },
          { name: 'ECDSA', status: 'implemented' },
          { name: 'Ed25519', status: 'implemented' },
          { name: 'Ed448', status: 'implemented' },
          { name: 'HMAC', status: 'implemented' },
        ],
      },
      { name: 'timingSafeEqual', status: 'implemented' },
    ],
  },
  {
    title: 'WebCrypto (Subtle)',
    items: [
      {
        name: 'crypto.subtle',
        subItems: [
          { name: 'decapsulateBits', status: 'missing' },
          { name: 'decapsulateKey', status: 'missing' },
          { name: 'encapsulateBits', status: 'missing' },
          { name: 'encapsulateKey', status: 'missing' },
          { name: 'getPublicKey', status: 'missing' },
          { name: 'supports', status: 'missing' },
        ],
      },
      {
        name: 'crypto.subtle.decrypt',
        subItems: [
          { name: 'RSA-OAEP', status: 'implemented' },
          { name: 'AES-CTR', status: 'implemented' },
          { name: 'AES-CBC', status: 'implemented' },
          { name: 'AES-GCM', status: 'implemented' },
          { name: 'ChaCha20-Poly1305', status: 'implemented' },
        ],
      },
      {
        name: 'crypto.subtle.deriveBits',
        subItems: [
          { name: 'ECDH', status: 'implemented' },
          { name: 'X25519', status: 'implemented' },
          { name: 'X448', status: 'implemented' },
          { name: 'HKDF', status: 'implemented' },
          { name: 'PBKDF2', status: 'implemented' },
        ],
      },
      {
        name: 'crypto.subtle.deriveKey',
        subItems: [
          { name: 'ECDH', status: 'missing' },
          { name: 'HKDF', status: 'implemented' },
          { name: 'PBKDF2', status: 'implemented' },
          { name: 'X25519', status: 'implemented' },
          { name: 'X448', status: 'implemented' },
        ],
      },
      {
        name: 'crypto.subtle.digest',
        subItems: [
          { name: 'cSHAKE128', status: 'missing' },
          { name: 'cSHAKE256', status: 'missing' },
          { name: 'SHA-1', status: 'implemented' },
          { name: 'SHA-256', status: 'implemented' },
          { name: 'SHA-384', status: 'implemented' },
          { name: 'SHA-512', status: 'implemented' },
          { name: 'SHA3-256', status: 'missing' },
          { name: 'SHA3-384', status: 'missing' },
          { name: 'SHA3-512', status: 'missing' },
        ],
      },
      {
        name: 'crypto.subtle.encrypt',
        subItems: [
          { name: 'AES-CTR', status: 'implemented' },
          { name: 'AES-CBC', status: 'implemented' },
          { name: 'AES-GCM', status: 'implemented' },
          { name: 'AES-OCB', status: 'missing' },
          { name: 'ChaCha20-Poly1305', status: 'implemented' },
          { name: 'RSA-OAEP', status: 'implemented' },
        ],
      },
      {
        name: 'crypto.subtle.exportKey',
        subItems: [
          { name: 'AES-CBC', status: 'partial', note: 'jwk, raw' },
          { name: 'AES-CTR', status: 'partial', note: 'jwk, raw, raw-secret' },
          { name: 'AES-GCM', status: 'partial', note: 'jwk, raw, raw-secret' },
          { name: 'AES-KW', status: 'partial', note: 'jwk, raw, raw-secret' },
          { name: 'AES-OCB', status: 'missing', note: 'Not implemented' },
          {
            name: 'ChaCha20-Poly1305',
            status: 'partial',
            note: 'jwk, raw',
          },
          {
            name: 'ECDH',
            status: 'partial',
            note: 'spki, pkcs8, jwk, raw, raw-public',
          },
          {
            name: 'ECDSA',
            status: 'partial',
            note: 'spki, pkcs8, jwk, raw, raw-public',
          },
          { name: 'Ed25519', status: 'partial', note: 'spki, pkcs8, raw' },
          { name: 'Ed448', status: 'partial', note: 'spki, pkcs8, raw' },
          { name: 'HMAC', status: 'partial', note: 'jwk, raw, raw-secret' },
          {
            name: 'ML-DSA-44',
            status: 'partial',
            note: 'spki, pkcs8, jwk, raw-public, raw-seed',
          },
          {
            name: 'ML-DSA-65',
            status: 'partial',
            note: 'spki, pkcs8, jwk, raw-public, raw-seed',
          },
          {
            name: 'ML-DSA-87',
            status: 'partial',
            note: 'spki, pkcs8, jwk, raw-public, raw-seed',
          },
          { name: 'ML-KEM-512', status: 'missing' },
          { name: 'ML-KEM-768', status: 'missing' },
          { name: 'ML-KEM-1024', status: 'missing' },
          { name: 'RSA-OAEP', status: 'partial', note: 'spki, pkcs8, jwk' },
          { name: 'RSA-PSS', status: 'partial', note: 'spki, pkcs8, jwk' },
          {
            name: 'RSASSA-PKCS1-v1_5',
            status: 'partial',
            note: 'spki, pkcs8, jwk',
          },
        ],
      },
      {
        name: 'crypto.subtle.generateKey',
        subItems: [
          { name: 'ECDH', status: 'implemented' },
          { name: 'ECDSA', status: 'implemented' },
          { name: 'Ed25519', status: 'implemented' },
          { name: 'Ed448', status: 'implemented' },
          { name: 'ML-DSA-44', status: 'implemented' },
          { name: 'ML-DSA-65', status: 'implemented' },
          { name: 'ML-DSA-87', status: 'implemented' },
          { name: 'ML-KEM-512', status: 'missing' },
          { name: 'ML-KEM-768', status: 'missing' },
          { name: 'ML-KEM-1024', status: 'missing' },
          { name: 'RSA-OAEP', status: 'implemented' },
          { name: 'RSA-PSS', status: 'implemented' },
          { name: 'RSASSA-PKCS1-v1_5', status: 'implemented' },
          { name: 'X25519', status: 'implemented' },
          { name: 'X448', status: 'implemented' },
          { name: 'AES-CTR', status: 'implemented' },
          { name: 'AES-CBC', status: 'implemented' },
          { name: 'AES-GCM', status: 'implemented' },
          { name: 'AES-KW', status: 'implemented' },
          { name: 'AES-OCB', status: 'missing' },
          { name: 'ChaCha20-Poly1305', status: 'implemented' },
          { name: 'HMAC', status: 'implemented' },
        ],
      },
      {
        name: 'crypto.subtle.importKey',
        subItems: [
          { name: 'AES-CBC', status: 'partial', note: 'jwk, raw, raw-secret' },
          { name: 'AES-CTR', status: 'partial', note: 'jwk, raw, raw-secret' },
          { name: 'AES-GCM', status: 'partial', note: 'jwk, raw, raw-secret' },
          { name: 'AES-KW', status: 'partial', note: 'jwk, raw, raw-secret' },
          { name: 'AES-OCB', status: 'missing' },
          { name: 'ChaCha20-Poly1305', status: 'partial', note: 'jwk, raw' },
          {
            name: 'ECDH',
            status: 'partial',
            note: 'spki, pkcs8, jwk, raw, raw-public',
          },
          {
            name: 'ECDSA',
            status: 'partial',
            note: 'spki, pkcs8, jwk, raw, raw-public',
          },
          { name: 'Ed25519', status: 'partial', note: 'spki, pkcs8' },
          { name: 'Ed448', status: 'partial', note: 'spki, pkcs8' },
          { name: 'HKDF', status: 'partial', note: 'raw' },
          { name: 'HMAC', status: 'partial', note: 'jwk, raw, raw-secret' },
          {
            name: 'ML-DSA-44',
            status: 'partial',
            note: 'spki, pkcs8, jwk, raw-public, raw-seed',
          },
          {
            name: 'ML-DSA-65',
            status: 'partial',
            note: 'spki, pkcs8, jwk, raw-public, raw-seed',
          },
          {
            name: 'ML-DSA-87',
            status: 'partial',
            note: 'spki, pkcs8, jwk, raw-public, raw-seed',
          },
          { name: 'ML-KEM-512', status: 'missing' },
          { name: 'ML-KEM-768', status: 'missing' },
          { name: 'ML-KEM-1024', status: 'missing' },
          { name: 'PBKDF2', status: 'partial', note: 'raw, raw-secret' },
          { name: 'RSA-OAEP', status: 'partial', note: 'spki, pkcs8, jwk' },
          { name: 'RSA-PSS', status: 'partial', note: 'spki, pkcs8, jwk' },
          {
            name: 'RSASSA-PKCS1-v1_5',
            status: 'partial',
            note: 'spki, pkcs8, jwk',
          },
          {
            name: 'X25519',
            status: 'partial',
            note: 'spki, pkcs8, jwk, raw, raw-public',
          },
          {
            name: 'X448',
            status: 'partial',
            note: 'spki, pkcs8, jwk, raw, raw-public',
          },
        ],
      },
      {
        name: 'crypto.subtle.sign',
        subItems: [
          { name: 'ECDSA', status: 'implemented' },
          { name: 'Ed25519', status: 'implemented' },
          { name: 'Ed448', status: 'implemented' },
          { name: 'HMAC', status: 'implemented' },
          { name: 'ML-DSA-44', status: 'implemented' },
          { name: 'ML-DSA-65', status: 'implemented' },
          { name: 'ML-DSA-87', status: 'implemented' },
          { name: 'RSA-PSS', status: 'implemented' },
          { name: 'RSASSA-PKCS1-v1_5', status: 'implemented' },
        ],
      },
      {
        name: 'crypto.subtle.unwrapKey',
        subItems: [
          { name: 'AES-GCM (Wraps)', status: 'implemented' },
          { name: 'AES-KW (Wraps)', status: 'implemented' },
          { name: 'ChaCha20-Poly1305 (Wraps)', status: 'implemented' },
          { name: 'AES-CBC (Wraps)', status: 'missing' },
          { name: 'AES-CTR (Wraps)', status: 'missing' },
          { name: 'AES-OCB (Wraps)', status: 'missing' },
          { name: 'RSA-OAEP (Wraps)', status: 'missing' },
        ],
      },
      {
        name: 'crypto.subtle.verify',
        subItems: [
          { name: 'ECDSA', status: 'implemented' },
          { name: 'Ed25519', status: 'implemented' },
          { name: 'Ed448', status: 'implemented' },
          { name: 'HMAC', status: 'implemented' },
          { name: 'ML-DSA-44', status: 'implemented' },
          { name: 'ML-DSA-65', status: 'implemented' },
          { name: 'ML-DSA-87', status: 'implemented' },
          { name: 'RSA-PSS', status: 'implemented' },
          { name: 'RSASSA-PKCS1-v1_5', status: 'implemented' },
        ],
      },
      {
        name: 'crypto.subtle.wrapKey',
        subItems: [
          { name: 'AES-GCM', status: 'implemented' },
          { name: 'AES-KW', status: 'implemented' },
          { name: 'ChaCha20-Poly1305', status: 'implemented' },
          { name: 'AES-CBC', status: 'missing' },
          { name: 'AES-CTR', status: 'missing' },
          { name: 'AES-OCB', status: 'missing' },
          { name: 'RSA-OAEP', status: 'missing' },
        ],
      },
    ],
  },
];
