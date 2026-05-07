import { NitroModules } from 'react-native-nitro-modules';
import { Buffer } from '@craftzdog/react-native-buffer';
import {
  CryptoKey,
  KeyObject,
  PrivateKeyObject,
  PublicKeyObject,
} from './keys/classes';
import {
  getUsagesUnion,
  hasAnyNotIn,
  lazyDOMException,
  normalizeHashName,
  KFormatType,
  KeyEncoding,
} from './utils';
import type {
  CryptoKeyPair,
  KeyUsage,
  RsaHashedKeyGenParams,
  SubtleAlgorithm,
  GenerateKeyPairOptions,
  KeyPairGenConfig,
} from './utils';
import type { RsaKeyPair } from './specs/rsaKeyPair.nitro';

export class Rsa {
  native: RsaKeyPair;

  constructor(
    modulusLength: number,
    publicExponent: Uint8Array,
    hashAlgorithm: string,
  ) {
    this.native = NitroModules.createHybridObject<RsaKeyPair>('RsaKeyPair');
    this.native.setModulusLength(modulusLength);
    this.native.setPublicExponent(
      publicExponent.buffer.slice(
        publicExponent.byteOffset,
        publicExponent.byteOffset + publicExponent.byteLength,
      ) as ArrayBuffer,
    );
    this.native.setHashAlgorithm(hashAlgorithm);
  }

  async generateKeyPair(): Promise<CryptoKeyPair> {
    await this.native.generateKeyPair();
    return {
      publicKey: this.native.getPublicKey(),
      privateKey: this.native.getPrivateKey(),
    };
  }

  generateKeyPairSync(): CryptoKeyPair {
    this.native.generateKeyPairSync();
    return {
      publicKey: this.native.getPublicKey(),
      privateKey: this.native.getPrivateKey(),
    };
  }
}

// Modern best practice (NIST SP 800-131A Rev. 2, IETF RFC 8017): RSA keys
// shorter than 2048 bits are deprecated for both signing and encryption.
// 1024-bit moduli have been factored in academic settings; 768-bit keys
// have been factored on commodity hardware. Reject anything below 2048
// at the JS boundary so callers can't accidentally generate weak keys.
const RSA_MIN_MODULUS_LENGTH = 2048;

// Node API
export async function rsa_generateKeyPair(
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKeyPair> {
  const { name, modulusLength, publicExponent, hash } =
    algorithm as RsaHashedKeyGenParams;

  // Validate parameters first
  if (!modulusLength || modulusLength < RSA_MIN_MODULUS_LENGTH) {
    throw lazyDOMException(
      `RSA modulusLength must be at least ${RSA_MIN_MODULUS_LENGTH} bits ` +
        `(got ${modulusLength ?? 0})`,
      'OperationError',
    );
  }

  if (!publicExponent || publicExponent.length === 0) {
    throw lazyDOMException('Invalid public exponent', 'OperationError');
  }

  // Validate hash algorithm using existing validation function
  let hashName: string;
  try {
    const normalizedHash = normalizeHashName(hash);
    hashName = typeof hash === 'string' ? hash : hash?.name || normalizedHash;
  } catch {
    throw lazyDOMException('Invalid Hash Algorithm', 'NotSupportedError');
  }

  // Validate usages are not empty
  if (keyUsages.length === 0) {
    throw lazyDOMException('Usages cannot be empty', 'SyntaxError');
  }

  // Usage validation based on algorithm type
  switch (name) {
    case 'RSASSA-PKCS1-v1_5':
      if (hasAnyNotIn(keyUsages, ['sign', 'verify'])) {
        throw lazyDOMException(
          `Unsupported key usage for a ${name} key`,
          'SyntaxError',
        );
      }
      break;
    case 'RSA-PSS':
      if (hasAnyNotIn(keyUsages, ['sign', 'verify'])) {
        throw lazyDOMException(
          `Unsupported key usage for a ${name} key`,
          'SyntaxError',
        );
      }
      break;
    case 'RSA-OAEP':
      if (
        hasAnyNotIn(keyUsages, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'])
      ) {
        throw lazyDOMException(
          `Unsupported key usage for a ${name} key`,
          'SyntaxError',
        );
      }
      break;
    default:
      throw lazyDOMException(
        'The algorithm is not supported',
        'NotSupportedError',
      );
  }

  // Split usages between public and private keys
  let publicUsages: KeyUsage[] = [];
  let privateUsages: KeyUsage[] = [];
  switch (name) {
    case 'RSASSA-PKCS1-v1_5':
    case 'RSA-PSS':
      publicUsages = getUsagesUnion(keyUsages, 'verify');
      privateUsages = getUsagesUnion(keyUsages, 'sign');
      break;
    case 'RSA-OAEP':
      publicUsages = getUsagesUnion(keyUsages, 'encrypt', 'wrapKey');
      privateUsages = getUsagesUnion(keyUsages, 'decrypt', 'unwrapKey');
      break;
  }

  // Validate that private key has usages for CryptoKeyPair
  if (privateUsages.length === 0) {
    throw lazyDOMException('Usages cannot be empty', 'SyntaxError');
  }

  const rsa = new Rsa(modulusLength, publicExponent, hashName);
  await rsa.generateKeyPair();

  const keyAlgorithm = {
    name,
    modulusLength,
    publicExponent,
    hash: { name: hashName },
  };

  // Create KeyObject instances using the standard createKeyObject method
  const publicKeyData = rsa.native.getPublicKey();
  const pub = KeyObject.createKeyObject(
    'public',
    publicKeyData,
  ) as PublicKeyObject;
  const publicKey = new CryptoKey(pub, keyAlgorithm, publicUsages, true);

  const privateKeyData = rsa.native.getPrivateKey();
  const priv = KeyObject.createKeyObject(
    'private',
    privateKeyData,
  ) as PrivateKeyObject;
  const privateKey = new CryptoKey(
    priv,
    keyAlgorithm,
    privateUsages,
    extractable,
  );

  return { publicKey, privateKey };
}

function rsa_prepareKeyGenParams(
  _type: 'rsa' | 'rsa-pss',
  options: GenerateKeyPairOptions | undefined,
): Rsa {
  if (!options) {
    throw new Error('Options are required for RSA key generation');
  }

  const {
    modulusLength,
    publicExponent,
    hash = 'sha256',
  } = options as {
    modulusLength?: number;
    publicExponent?: number;
    hash?: string;
  };

  if (!modulusLength || modulusLength < RSA_MIN_MODULUS_LENGTH) {
    throw new RangeError(
      `RSA modulusLength must be at least ${RSA_MIN_MODULUS_LENGTH} bits ` +
        `(got ${modulusLength ?? 0})`,
    );
  }

  const pubExp = publicExponent || 65537;
  const pubExpBytes = new Uint8Array([
    (pubExp >> 16) & 0xff,
    (pubExp >> 8) & 0xff,
    pubExp & 0xff,
  ]);

  const hashName = typeof hash === 'string' ? hash : hash;

  return new Rsa(modulusLength, pubExpBytes, hashName);
}

function rsa_formatKeyPairOutput(
  rsa: Rsa,
  encoding: KeyPairGenConfig,
): {
  publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
  privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;
} {
  const {
    publicFormat,
    publicType,
    privateFormat,
    privateType,
    cipher,
    passphrase,
  } = encoding;

  const publicKeyData = rsa.native.getPublicKey();
  const privateKeyData = rsa.native.getPrivateKey();

  const pub = KeyObject.createKeyObject(
    'public',
    publicKeyData,
  ) as PublicKeyObject;

  const priv = KeyObject.createKeyObject(
    'private',
    privateKeyData,
  ) as PrivateKeyObject;

  let publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
  let privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;

  if (
    publicFormat === 'raw-public' ||
    privateFormat === 'raw-private' ||
    privateFormat === 'raw-seed'
  ) {
    throw new Error('Raw key formats are not supported for RSA keys');
  }

  if (publicFormat === -1) {
    publicKey = pub;
  } else {
    const format =
      publicFormat === KFormatType.PEM ? KFormatType.PEM : KFormatType.DER;
    const keyEncoding =
      publicType === KeyEncoding.SPKI ? KeyEncoding.SPKI : KeyEncoding.PKCS1;
    const exported = pub.handle.exportKey(format, keyEncoding);
    if (format === KFormatType.PEM) {
      publicKey = Buffer.from(new Uint8Array(exported)).toString('utf-8');
    } else {
      publicKey = exported;
    }
  }

  if (privateFormat === -1) {
    privateKey = priv;
  } else {
    const format =
      privateFormat === KFormatType.PEM ? KFormatType.PEM : KFormatType.DER;
    const keyEncoding =
      privateType === KeyEncoding.PKCS8 ? KeyEncoding.PKCS8 : KeyEncoding.PKCS1;
    const exported = priv.handle.exportKey(
      format,
      keyEncoding,
      cipher,
      passphrase,
    );
    if (format === KFormatType.PEM) {
      privateKey = Buffer.from(new Uint8Array(exported)).toString('utf-8');
    } else {
      privateKey = exported;
    }
  }

  return { publicKey, privateKey };
}

export async function rsa_generateKeyPairNode(
  type: 'rsa' | 'rsa-pss',
  options: GenerateKeyPairOptions | undefined,
  encoding: KeyPairGenConfig,
): Promise<{
  publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
  privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;
}> {
  const rsa = rsa_prepareKeyGenParams(type, options);
  await rsa.generateKeyPair();
  return rsa_formatKeyPairOutput(rsa, encoding);
}

export function rsa_generateKeyPairNodeSync(
  type: 'rsa' | 'rsa-pss',
  options: GenerateKeyPairOptions | undefined,
  encoding: KeyPairGenConfig,
): {
  publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
  privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;
} {
  const rsa = rsa_prepareKeyGenParams(type, options);
  rsa.generateKeyPairSync();
  return rsa_formatKeyPairOutput(rsa, encoding);
}
