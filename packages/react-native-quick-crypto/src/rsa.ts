import { NitroModules } from 'react-native-nitro-modules';
import {
  CryptoKey,
  KeyObject,
  PrivateKeyObject,
  PublicKeyObject,
} from './keys';
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

// Node API
export async function rsa_generateKeyPair(
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKeyPair> {
  const { name, modulusLength, publicExponent, hash } =
    algorithm as RsaHashedKeyGenParams;

  // Validate parameters first
  if (!modulusLength || modulusLength < 256) {
    throw lazyDOMException('Invalid key length', 'OperationError');
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

export async function rsa_generateKeyPairNode(
  type: 'rsa' | 'rsa-pss',
  options: GenerateKeyPairOptions | undefined,
  encoding: KeyPairGenConfig,
): Promise<{
  publicKey: PublicKeyObject | Buffer | string;
  privateKey: PrivateKeyObject | Buffer | string;
}> {
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

  if (!modulusLength || modulusLength < 256) {
    throw new Error('Invalid modulus length');
  }

  const pubExp = publicExponent || 65537;
  const pubExpBytes = new Uint8Array([
    (pubExp >> 16) & 0xff,
    (pubExp >> 8) & 0xff,
    pubExp & 0xff,
  ]);

  const algorithmName = type === 'rsa-pss' ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5';

  const algorithm: RsaHashedKeyGenParams = {
    name: algorithmName,
    modulusLength,
    publicExponent: pubExpBytes,
    hash: typeof hash === 'string' ? hash : hash,
  };

  const keyPair = await rsa_generateKeyPair(
    algorithm as SubtleAlgorithm,
    true,
    ['sign', 'verify'],
  );

  // rsa_generateKeyPair returns CryptoKey objects
  const pubCryptoKey = keyPair.publicKey as CryptoKey;
  const privCryptoKey = keyPair.privateKey as CryptoKey;

  const {
    publicFormat,
    publicType,
    privateFormat,
    privateType,
    cipher,
    passphrase,
  } = encoding;

  let publicKey: PublicKeyObject | Buffer | string;
  let privateKey: PrivateKeyObject | Buffer | string;

  if (publicFormat === -1) {
    publicKey = pubCryptoKey.keyObject as PublicKeyObject;
  } else {
    const format =
      publicFormat === KFormatType.PEM ? KFormatType.PEM : KFormatType.DER;
    const keyEncoding =
      publicType === KeyEncoding.SPKI ? KeyEncoding.SPKI : KeyEncoding.PKCS1;
    const exported = pubCryptoKey.keyObject.handle.exportKey(
      format,
      keyEncoding,
    );
    // For PEM format, convert ArrayBuffer to string; for DER, keep as ArrayBuffer
    if (format === KFormatType.PEM) {
      publicKey = Buffer.from(new Uint8Array(exported)).toString('utf-8');
    } else {
      // Return raw ArrayBuffer for DER format
      publicKey = Buffer.from(new Uint8Array(exported));
    }
  }

  if (privateFormat === -1) {
    privateKey = privCryptoKey.keyObject as PrivateKeyObject;
  } else {
    const format =
      privateFormat === KFormatType.PEM ? KFormatType.PEM : KFormatType.DER;
    const keyEncoding =
      privateType === KeyEncoding.PKCS8 ? KeyEncoding.PKCS8 : KeyEncoding.PKCS1;
    const exported = privCryptoKey.keyObject.handle.exportKey(
      format,
      keyEncoding,
      cipher,
      passphrase,
    );
    // For PEM format, convert ArrayBuffer to string; for DER, keep as ArrayBuffer
    if (format === KFormatType.PEM) {
      privateKey = Buffer.from(new Uint8Array(exported)).toString('utf-8');
    } else {
      // Return raw ArrayBuffer for DER format
      privateKey = Buffer.from(new Uint8Array(exported));
    }
  }

  return { publicKey, privateKey };
}
