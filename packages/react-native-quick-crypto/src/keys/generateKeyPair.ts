import { ed_generateKeyPair } from '../ed';
import { Buffer } from '@craftzdog/react-native-buffer';
import { rsa_generateKeyPairNode, rsa_generateKeyPairNodeSync } from '../rsa';
import { ec_generateKeyPairNode, ec_generateKeyPairNodeSync } from '../ec';
import { dsa_generateKeyPairNode, dsa_generateKeyPairNodeSync } from '../dsa';
import {
  dh_generateKeyPairNode,
  dh_generateKeyPairNodeSync,
} from '../dhKeyPair';
import { SlhDsa, type SlhDsaVariant } from '../slhdsa';
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
  type SlhDsaKeyPairType,
  KFormatType,
  KeyEncoding,
} from '../utils';
import {
  KeyObject,
  type PublicKeyObject,
  type PrivateKeyObject,
} from './classes';
import { parsePrivateKeyEncoding, parsePublicKeyEncoding } from './utils';

const SLH_DSA_TYPE_TO_VARIANT: Readonly<
  Record<SlhDsaKeyPairType, SlhDsaVariant>
> = {
  'slh-dsa-sha2-128s': 'SLH-DSA-SHA2-128s',
  'slh-dsa-sha2-128f': 'SLH-DSA-SHA2-128f',
  'slh-dsa-sha2-192s': 'SLH-DSA-SHA2-192s',
  'slh-dsa-sha2-192f': 'SLH-DSA-SHA2-192f',
  'slh-dsa-sha2-256s': 'SLH-DSA-SHA2-256s',
  'slh-dsa-sha2-256f': 'SLH-DSA-SHA2-256f',
  'slh-dsa-shake-128s': 'SLH-DSA-SHAKE-128s',
  'slh-dsa-shake-128f': 'SLH-DSA-SHAKE-128f',
  'slh-dsa-shake-192s': 'SLH-DSA-SHAKE-192s',
  'slh-dsa-shake-192f': 'SLH-DSA-SHAKE-192f',
  'slh-dsa-shake-256s': 'SLH-DSA-SHAKE-256s',
  'slh-dsa-shake-256f': 'SLH-DSA-SHAKE-256f',
};

function isSlhDsaType(type: string): type is SlhDsaKeyPairType {
  return type in SLH_DSA_TYPE_TO_VARIANT;
}

function slhDsaFormatKeyPairOutput(
  slhdsa: SlhDsa,
  encoding: KeyPairGenConfig,
): {
  publicKey: PublicKeyObject | string | ArrayBuffer | Buffer;
  privateKey: PrivateKeyObject | string | ArrayBuffer | Buffer;
} {
  const { publicFormat, privateFormat, cipher, passphrase } = encoding;

  const publicKey = KeyObject.createKeyObject(
    'public',
    slhdsa.getPublicKey(),
    KFormatType.DER,
    KeyEncoding.SPKI,
  ) as PublicKeyObject;
  const privateKey = KeyObject.createKeyObject(
    'private',
    slhdsa.getPrivateKey(),
    KFormatType.DER,
    KeyEncoding.PKCS8,
  ) as PrivateKeyObject;

  let publicKeyOutput: PublicKeyObject | string | ArrayBuffer | Buffer;
  let privateKeyOutput: PrivateKeyObject | string | ArrayBuffer | Buffer;

  if (publicFormat === -1) {
    publicKeyOutput = publicKey;
  } else if (publicFormat === 'raw-public') {
    publicKeyOutput = Buffer.from(publicKey.handle.exportRawPublic());
  } else {
    const format =
      publicFormat === KFormatType.PEM ? KFormatType.PEM : KFormatType.DER;
    const exported = publicKey.handle.exportKey(format, KeyEncoding.SPKI);
    if (format === KFormatType.PEM) {
      publicKeyOutput = Buffer.from(new Uint8Array(exported)).toString('utf-8');
    } else {
      publicKeyOutput = exported;
    }
  }

  if (privateFormat === -1) {
    privateKeyOutput = privateKey;
  } else if (privateFormat === 'raw-private') {
    privateKeyOutput = Buffer.from(privateKey.handle.exportRawPrivate());
  } else if (privateFormat === 'raw-seed') {
    privateKeyOutput = Buffer.from(privateKey.handle.exportRawSeed());
  } else {
    const format =
      privateFormat === KFormatType.PEM ? KFormatType.PEM : KFormatType.DER;
    const exported = privateKey.handle.exportKey(
      format,
      KeyEncoding.PKCS8,
      cipher,
      passphrase,
    );
    if (format === KFormatType.PEM) {
      privateKeyOutput = Buffer.from(new Uint8Array(exported)).toString(
        'utf-8',
      );
    } else {
      privateKeyOutput = exported;
    }
  }

  return { publicKey: publicKeyOutput, privateKey: privateKeyOutput };
}

function slhDsaGenerateKeyPairNodeSync(
  type: SlhDsaKeyPairType,
  encoding: KeyPairGenConfig,
): {
  publicKey: PublicKeyObject | string | ArrayBuffer | Buffer;
  privateKey: PrivateKeyObject | string | ArrayBuffer | Buffer;
} {
  const slhdsa = new SlhDsa(SLH_DSA_TYPE_TO_VARIANT[type]);
  slhdsa.generateKeyPairSync();
  return slhDsaFormatKeyPairOutput(slhdsa, encoding);
}

async function slhDsaGenerateKeyPairNode(
  type: SlhDsaKeyPairType,
  encoding: KeyPairGenConfig,
): Promise<{
  publicKey: PublicKeyObject | string | ArrayBuffer | Buffer;
  privateKey: PrivateKeyObject | string | ArrayBuffer | Buffer;
}> {
  const slhdsa = new SlhDsa(SLH_DSA_TYPE_TO_VARIANT[type]);
  await slhdsa.generateKeyPair();
  return slhDsaFormatKeyPairOutput(slhdsa, encoding);
}

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
export type KeyObjectKeyPair = {
  publicKey: PublicKeyObject;
  privateKey: PrivateKeyObject;
};

type KeyObjectGenerateKeyPairOptions = Omit<
  GenerateKeyPairOptions,
  'publicKeyEncoding' | 'privateKeyEncoding'
> & {
  publicKeyEncoding?: undefined;
  privateKeyEncoding?: undefined;
};

export function generateKeyPairSync(type: KeyPairType): KeyObjectKeyPair;
export function generateKeyPairSync(
  type: KeyPairType,
  options: KeyObjectGenerateKeyPairOptions,
): KeyObjectKeyPair;
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
    publicFormat: publicFormat as KeyPairGenConfig['publicFormat'],
    publicType: publicType as KeyPairGenConfig['publicType'],
    privateFormat: privateFormat as KeyPairGenConfig['privateFormat'],
    privateType: privateType as KeyPairGenConfig['privateType'],
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
    case 'dh':
      break;
    default: {
      if (isSlhDsaType(type)) {
        break;
      }
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
        } else if (type === 'dsa') {
          result = await dsa_generateKeyPairNode(options, encoding);
        } else if (type === 'dh') {
          result = await dh_generateKeyPairNode(options, encoding);
        } else if (isSlhDsaType(type)) {
          result = await slhDsaGenerateKeyPairNode(type, encoding);
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
    } else if (type === 'dsa') {
      result = dsa_generateKeyPairNodeSync(options, encoding);
    } else if (type === 'dh') {
      result = dh_generateKeyPairNodeSync(options, encoding);
    } else if (isSlhDsaType(type)) {
      result = slhDsaGenerateKeyPairNodeSync(type, encoding);
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
