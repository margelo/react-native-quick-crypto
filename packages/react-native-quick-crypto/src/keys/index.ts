import {
  AsymmetricKeyObject,
  CryptoKey,
  KeyObject,
  SecretKeyObject,
  PublicKeyObject,
  PrivateKeyObject,
} from './classes';
import { generateKeyPair, generateKeyPairSync } from './generateKeyPair';
import {
  createSign,
  createVerify,
  sign,
  verify,
  Sign,
  Verify,
} from './signVerify';
import {
  publicEncrypt,
  publicDecrypt,
  privateEncrypt,
  privateDecrypt,
} from './publicCipher';
import {
  isCryptoKey,
  parseKeyEncoding,
  parsePrivateKeyEncoding,
  parsePublicKeyEncoding,
} from './utils';
import { NitroModules } from 'react-native-nitro-modules';
import type { BinaryLike, JWK, KeyObjectHandle } from '../utils';
import {
  binaryLikeToArrayBuffer as toAB,
  isStringOrBuffer,
  KFormatType,
  KeyEncoding,
  KeyType,
} from '../utils';
import { randomBytes } from '../random';

interface KeyInputObject {
  key: BinaryLike | KeyObject | CryptoKey | JWK;
  format?: 'pem' | 'der' | 'jwk' | 'raw-public' | 'raw-private' | 'raw-seed';
  type?: 'pkcs1' | 'pkcs8' | 'spki' | 'sec1';
  passphrase?: BinaryLike;
  encoding?: BufferEncoding;
  asymmetricKeyType?: string;
  namedCurve?: string;
}

type KeyInput = BinaryLike | KeyInputObject | KeyObject | CryptoKey;

function isRawFormat(
  format: string | undefined,
): format is 'raw-public' | 'raw-private' | 'raw-seed' {
  return (
    format === 'raw-public' || format === 'raw-private' || format === 'raw-seed'
  );
}

function createPublicKeyFromRaw(input: KeyInputObject): PublicKeyObject {
  if (input.format !== 'raw-public') {
    throw new Error('Invalid format for createPublicKey raw import');
  }
  if (typeof input.asymmetricKeyType !== 'string') {
    throw new Error('options.asymmetricKeyType is required for raw key import');
  }
  if (input.asymmetricKeyType === 'ec' && !input.namedCurve) {
    throw new Error('options.namedCurve is required for EC raw key import');
  }
  const handle =
    NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
  handle.initRawPublic(
    input.asymmetricKeyType,
    toAB(input.key as BinaryLike),
    input.namedCurve,
  );
  return new PublicKeyObject(handle);
}

function createPrivateKeyFromRaw(input: KeyInputObject): PrivateKeyObject {
  if (input.format !== 'raw-private' && input.format !== 'raw-seed') {
    throw new Error('Invalid format for createPrivateKey raw import');
  }
  if (typeof input.asymmetricKeyType !== 'string') {
    throw new Error('options.asymmetricKeyType is required for raw key import');
  }
  if (input.asymmetricKeyType === 'ec' && !input.namedCurve) {
    throw new Error('options.namedCurve is required for EC raw key import');
  }
  const handle =
    NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
  if (input.format === 'raw-seed') {
    handle.initRawSeed(input.asymmetricKeyType, toAB(input.key as BinaryLike));
  } else {
    handle.initRawPrivate(
      input.asymmetricKeyType,
      toAB(input.key as BinaryLike),
      input.namedCurve,
    );
  }
  return new PrivateKeyObject(handle);
}

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

    // Filter to only 'pem' or 'der' — JWK and raw formats are handled
    // separately via dedicated paths.
    const filteredFormat: 'pem' | 'der' | undefined =
      format === 'pem' || format === 'der' ? format : undefined;
    return { data: toAB(data), format: filteredFormat, type };
  }

  throw new Error('Invalid key input');
}

function createPublicKey(key: KeyInput): PublicKeyObject {
  if (typeof key === 'object' && 'key' in key && isRawFormat(key.format)) {
    if (key.format !== 'raw-public') {
      throw new Error(
        `Invalid format ${key.format} for createPublicKey — only 'raw-public' is allowed`,
      );
    }
    return createPublicKeyFromRaw(key as KeyInputObject);
  }
  if (typeof key === 'object' && 'key' in key && key.format === 'jwk') {
    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    const keyType = handle.initJwk(key.key as JWK);
    if (keyType === undefined) {
      throw new Error('Failed to import JWK');
    }
    if (keyType === KeyType.PRIVATE) {
      // Extract public from private
      const exported = handle.exportKey(KFormatType.DER, KeyEncoding.SPKI);
      const pubHandle =
        NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
      pubHandle.init(
        KeyType.PUBLIC,
        exported,
        KFormatType.DER,
        KeyEncoding.SPKI,
      );
      return new PublicKeyObject(pubHandle);
    }
    return new PublicKeyObject(handle);
  }

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
  if (typeof key === 'object' && 'key' in key && isRawFormat(key.format)) {
    if (key.format === 'raw-public') {
      throw new Error("Invalid format 'raw-public' for createPrivateKey");
    }
    return createPrivateKeyFromRaw(key as KeyInputObject);
  }
  if (typeof key === 'object' && 'key' in key && key.format === 'jwk') {
    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    const keyType = handle.initJwk(key.key as JWK);
    if (keyType === undefined || keyType !== KeyType.PRIVATE) {
      throw new Error('Failed to import private key from JWK');
    }
    return new PrivateKeyObject(handle);
  }

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

export interface GenerateKeyOptions {
  length: number;
}

function generateKeySync(
  type: 'aes' | 'hmac',
  options: GenerateKeyOptions,
): SecretKeyObject {
  if (typeof type !== 'string') {
    throw new TypeError('The "type" argument must be a string');
  }
  if (typeof options !== 'object' || options === null) {
    throw new TypeError('The "options" argument must be an object');
  }

  const { length } = options;

  if (typeof length !== 'number' || !Number.isInteger(length)) {
    throw new TypeError('The "options.length" property must be an integer');
  }

  switch (type) {
    case 'hmac':
      if (length < 8 || length > 2 ** 31 - 1) {
        throw new RangeError(
          'The "options.length" property must be >= 8 and <= 2147483647',
        );
      }
      break;
    case 'aes':
      if (length !== 128 && length !== 192 && length !== 256) {
        throw new RangeError(
          'The "options.length" property must be 128, 192, or 256',
        );
      }
      break;
    default:
      throw new TypeError(
        `The "type" argument must be 'aes' or 'hmac'. Received '${type}'`,
      );
  }

  const keyBytes = length / 8;
  const keyMaterial = randomBytes(keyBytes);
  return createSecretKey(keyMaterial);
}

function generateKey(
  type: 'aes' | 'hmac',
  options: GenerateKeyOptions,
  callback: (err: Error | null, key?: SecretKeyObject) => void,
): void {
  if (typeof callback !== 'function') {
    throw new TypeError('The "callback" argument must be a function');
  }

  try {
    const key = generateKeySync(type, options);
    process.nextTick(callback, null, key);
  } catch (err) {
    process.nextTick(callback, err as Error);
  }
}

export {
  // Node Public API
  createSecretKey,
  createPublicKey,
  createPrivateKey,
  CryptoKey,
  generateKey,
  generateKeySync,
  generateKeyPair,
  generateKeyPairSync,
  AsymmetricKeyObject,
  KeyObject,
  createSign,
  createVerify,
  sign,
  verify,
  Sign,
  Verify,
  publicEncrypt,
  publicDecrypt,
  privateEncrypt,
  privateDecrypt,

  // Node Internal API
  parsePublicKeyEncoding,
  parsePrivateKeyEncoding,
  parseKeyEncoding,
  SecretKeyObject,
  PublicKeyObject,
  PrivateKeyObject,
  isCryptoKey,
};
