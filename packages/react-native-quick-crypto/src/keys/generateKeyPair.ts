import { ed_generateKeyPair } from '../ed';
import { rsa_generateKeyPairNode, rsa_generateKeyPairNodeSync } from '../rsa';
import { ec_generateKeyPairNode, ec_generateKeyPairNodeSync } from '../ec';
import {
  kEmptyObject,
  validateFunction,
  type CryptoKeyPair,
  type GenerateKeyPairCallback,
  type GenerateKeyPairOptions,
  type GenerateKeyPairPromiseReturn,
  type GenerateKeyPairReturn,
  type KeyPairGenConfig,
  type KeyPairKey,
  type KeyPairType,
} from '../utils';
import { parsePrivateKeyEncoding, parsePublicKeyEncoding } from './utils';

export const generateKeyPair = (
  type: KeyPairType,
  options: GenerateKeyPairOptions,
  callback: GenerateKeyPairCallback,
): void => {
  validateFunction(callback);
  internalGenerateKeyPair(true, type, options, callback);
};

// Promisify generateKeyPair
// (attempted to use util.promisify, to no avail)
export const generateKeyPairPromise = (
  type: KeyPairType,
  options: GenerateKeyPairOptions,
): Promise<GenerateKeyPairPromiseReturn> => {
  return new Promise((resolve, reject) => {
    generateKeyPair(type, options, (err, publicKey, privateKey) => {
      if (err) {
        reject([err, undefined]);
      } else {
        resolve([undefined, { publicKey, privateKey }]);
      }
    });
  });
};

// generateKeyPairSync
export function generateKeyPairSync(type: KeyPairType): CryptoKeyPair;
export function generateKeyPairSync(
  type: KeyPairType,
  options: GenerateKeyPairOptions,
): CryptoKeyPair;
export function generateKeyPairSync(
  type: KeyPairType,
  options?: GenerateKeyPairOptions,
): CryptoKeyPair {
  const [err, publicKey, privateKey] = internalGenerateKeyPair(
    false,
    type,
    options,
    undefined,
  )!;

  if (err) {
    throw err;
  }

  return {
    publicKey,
    privateKey,
  };
}

function parseKeyPairEncoding(
  keyType: string,
  options: GenerateKeyPairOptions = kEmptyObject,
): KeyPairGenConfig {
  const { publicKeyEncoding, privateKeyEncoding } = options;

  let publicFormat, publicType;
  if (publicKeyEncoding == null) {
    publicFormat = publicType = -1;
  } else if (typeof publicKeyEncoding === 'object') {
    ({ format: publicFormat, type: publicType } = parsePublicKeyEncoding(
      publicKeyEncoding,
      keyType,
      'publicKeyEncoding',
    ));
  } else {
    throw new Error(
      'Invalid argument options.publicKeyEncoding',
      publicKeyEncoding,
    );
  }

  let privateFormat, privateType, cipher, passphrase;
  if (privateKeyEncoding == null) {
    privateFormat = privateType = -1;
  } else if (typeof privateKeyEncoding === 'object') {
    ({
      format: privateFormat,
      type: privateType,
      cipher,
      passphrase,
    } = parsePrivateKeyEncoding(
      privateKeyEncoding,
      keyType,
      'privateKeyEncoding',
    ));
  } else {
    throw new Error(
      'Invalid argument options.privateKeyEncoding',
      publicKeyEncoding as ErrorOptions,
    );
  }

  return {
    publicFormat,
    publicType,
    privateFormat,
    privateType,
    cipher,
    passphrase,
  };
}

function internalGenerateKeyPair(
  isAsync: boolean,
  type: KeyPairType,
  options: GenerateKeyPairOptions | undefined,
  callback: GenerateKeyPairCallback | undefined,
): GenerateKeyPairReturn | void {
  const encoding = parseKeyPairEncoding(type, options);

  switch (type) {
    case 'ed25519':
    case 'ed448':
    case 'x25519':
    case 'x448':
      return ed_generateKeyPair(isAsync, type, encoding, callback);
    case 'rsa':
    case 'rsa-pss':
    case 'dsa':
    case 'ec':
      break;
    default: {
      const err = new Error(`
        Invalid Argument options: '${type}' scheme not supported for
        generateKeyPair(). Currently not all encryption methods are supported in
        this library.  Check docs/implementation_coverage.md for status.
      `);
      return [err, undefined, undefined];
    }
  }

  if (isAsync) {
    const impl = async (): Promise<GenerateKeyPairReturn> => {
      try {
        let result;
        if (type === 'rsa' || type === 'rsa-pss') {
          result = await rsa_generateKeyPairNode(type, options, encoding);
        } else if (type === 'ec') {
          result = await ec_generateKeyPairNode(options, encoding);
        } else {
          throw new Error(`Unsupported key type: ${type}`);
        }
        return [
          undefined,
          result.publicKey as KeyPairKey,
          result.privateKey as KeyPairKey,
        ];
      } catch (error) {
        return [error as Error, undefined, undefined];
      }
    };

    impl().then(result => {
      const [err, publicKey, privateKey] = result;
      callback!(err, publicKey, privateKey);
    });
    return;
  }

  try {
    let result;
    if (type === 'rsa' || type === 'rsa-pss') {
      result = rsa_generateKeyPairNodeSync(type, options, encoding);
    } else if (type === 'ec') {
      result = ec_generateKeyPairNodeSync(options, encoding);
    } else {
      throw new Error(`Unsupported key type: ${type}`);
    }
    return [
      undefined,
      result.publicKey as KeyPairKey,
      result.privateKey as KeyPairKey,
    ];
  } catch (error) {
    return [error as Error, undefined, undefined];
  }
}
