import {
  AsymmetricKeyObject,
  CryptoKey,
  KeyObject,
  SecretKeyObject,
  PublicKeyObject,
  PrivateKeyObject,
} from './classes';
import { generateKeyPair, generateKeyPairSync } from './generateKeyPair';
import { createSign, createVerify, Sign, Verify } from './signVerify';
import { publicEncrypt, publicDecrypt } from './publicCipher';
import {
  isCryptoKey,
  parseKeyEncoding,
  parsePrivateKeyEncoding,
  parsePublicKeyEncoding,
} from './utils';
import type { BinaryLike } from '../utils';
import {
  binaryLikeToArrayBuffer as toAB,
  isStringOrBuffer,
  KFormatType,
  KeyEncoding,
} from '../utils';

interface KeyInputObject {
  key: BinaryLike | KeyObject | CryptoKey;
  format?: 'pem' | 'der' | 'jwk';
  type?: 'pkcs1' | 'pkcs8' | 'spki' | 'sec1';
  passphrase?: BinaryLike;
  encoding?: BufferEncoding;
}

type KeyInput = BinaryLike | KeyInputObject | KeyObject | CryptoKey;

function createSecretKey(key: BinaryLike): SecretKeyObject {
  const keyBuffer = toAB(key);
  return KeyObject.createKeyObject('secret', keyBuffer) as SecretKeyObject;
}

function prepareAsymmetricKey(
  key: KeyInput,
  isPublic: boolean,
): {
  data: ArrayBuffer;
  format?: 'pem' | 'der';
  type?: 'pkcs1' | 'pkcs8' | 'spki' | 'sec1';
} {
  if (key instanceof KeyObject) {
    if (isPublic) {
      // createPublicKey can accept either a public key or extract public from private
      if (key.type === 'secret') {
        throw new Error('Cannot create public key from secret key');
      }
      // Export as SPKI (public key format) - works for both public and private keys
      const exported = key.handle.exportKey(KFormatType.DER, KeyEncoding.SPKI);
      return { data: exported, format: 'der', type: 'spki' };
    } else {
      // createPrivateKey requires a private key
      if (key.type !== 'private') {
        throw new Error('Key must be a private key');
      }
      const exported = key.handle.exportKey(KFormatType.DER, KeyEncoding.PKCS8);
      return { data: exported, format: 'der', type: 'pkcs8' };
    }
  }

  if (isCryptoKey(key)) {
    const cryptoKey = key as CryptoKey;
    return prepareAsymmetricKey(cryptoKey.keyObject, isPublic);
  }

  if (isStringOrBuffer(key)) {
    // Detect PEM format from string content
    const isPem = typeof key === 'string' && key.includes('-----BEGIN');
    return { data: toAB(key), format: isPem ? 'pem' : undefined };
  }

  if (typeof key === 'object' && 'key' in key) {
    const keyObj = key as KeyInputObject;
    const { key: data, format, type } = keyObj;

    if (data instanceof KeyObject) {
      return prepareAsymmetricKey(data, isPublic);
    }

    if (isCryptoKey(data)) {
      return prepareAsymmetricKey((data as CryptoKey).keyObject, isPublic);
    }

    if (!isStringOrBuffer(data)) {
      throw new Error('Invalid key data type');
    }

    // For PEM format with string data, convert to ArrayBuffer
    if (
      (format === 'pem' ||
        (typeof data === 'string' && data.includes('-----BEGIN'))) &&
      typeof data === 'string'
    ) {
      return { data: toAB(data), format: 'pem', type };
    }

    // Filter out 'jwk' format - only 'pem' and 'der' are supported here
    const filteredFormat = format === 'jwk' ? undefined : format;
    return { data: toAB(data), format: filteredFormat, type };
  }

  throw new Error('Invalid key input');
}

function createPublicKey(key: KeyInput): PublicKeyObject {
  const { data, format, type } = prepareAsymmetricKey(key, true);

  // Map format string to KFormatType enum
  let kFormat: KFormatType | undefined;
  if (format === 'pem') kFormat = KFormatType.PEM;
  else if (format === 'der') kFormat = KFormatType.DER;

  // Map type string to KeyEncoding enum
  let kType: KeyEncoding | undefined;
  if (type === 'spki') kType = KeyEncoding.SPKI;
  else if (type === 'pkcs1') kType = KeyEncoding.PKCS1;

  return KeyObject.createKeyObject(
    'public',
    data,
    kFormat,
    kType,
  ) as PublicKeyObject;
}

function createPrivateKey(key: KeyInput): PrivateKeyObject {
  const { data, format, type } = prepareAsymmetricKey(key, false);

  // Map format string to KFormatType enum
  let kFormat: KFormatType | undefined;
  if (format === 'pem') kFormat = KFormatType.PEM;
  else if (format === 'der') kFormat = KFormatType.DER;

  // Map type string to KeyEncoding enum
  let kType: KeyEncoding | undefined;
  if (type === 'pkcs8') kType = KeyEncoding.PKCS8;
  else if (type === 'pkcs1') kType = KeyEncoding.PKCS1;
  else if (type === 'sec1') kType = KeyEncoding.SEC1;

  return KeyObject.createKeyObject(
    'private',
    data,
    kFormat,
    kType,
  ) as PrivateKeyObject;
}

export {
  // Node Public API
  createSecretKey,
  createPublicKey,
  createPrivateKey,
  CryptoKey,
  generateKeyPair,
  generateKeyPairSync,
  AsymmetricKeyObject,
  KeyObject,
  createSign,
  createVerify,
  Sign,
  Verify,
  publicEncrypt,
  publicDecrypt,

  // Node Internal API
  parsePublicKeyEncoding,
  parsePrivateKeyEncoding,
  parseKeyEncoding,
  SecretKeyObject,
  PublicKeyObject,
  PrivateKeyObject,
  isCryptoKey,
};
