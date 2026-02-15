import { NitroModules } from 'react-native-nitro-modules';
import type { EcKeyPair } from './specs/ecKeyPair.nitro';
import type { KeyObjectHandle } from './specs/keyObjectHandle.nitro';
import {
  CryptoKey,
  KeyObject,
  PublicKeyObject,
  PrivateKeyObject,
} from './keys/classes';
import type {
  CryptoKeyPair,
  KeyPairOptions,
  KeyUsage,
  SubtleAlgorithm,
  BufferLike,
  BinaryLike,
  JWK,
  ImportFormat,
  NamedCurve,
  GenerateKeyPairOptions,
  KeyPairGenConfig,
} from './utils/types';
import {
  bufferLikeToArrayBuffer,
  getUsagesUnion,
  hasAnyNotIn,
  kNamedCurveAliases,
  lazyDOMException,
  normalizeHashName,
  HashContext,
  KeyEncoding,
  KFormatType,
} from './utils';
import { Buffer } from '@craftzdog/react-native-buffer';
import { ECDH } from './ecdh';

class EcUtils {
  private static _native: EcKeyPair | undefined;
  private static get native(): EcKeyPair {
    if (!this._native) {
      this._native = NitroModules.createHybridObject<EcKeyPair>('EcKeyPair');
    }
    return this._native;
  }
  public static getSupportedCurves(): string[] {
    return this.native.getSupportedCurves();
  }
}

export function getCurves(): string[] {
  return EcUtils.getSupportedCurves();
}

export class Ec {
  native: EcKeyPair;

  constructor(curve: string) {
    this.native = NitroModules.createHybridObject<EcKeyPair>('EcKeyPair');
    this.native.setCurve(curve);
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

// WebCrypto API — only P-256, P-384, P-521 allowed per spec
export function ecImportKey(
  format: ImportFormat,
  keyData: BufferLike | BinaryLike | JWK,
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): CryptoKey {
  const { name, namedCurve } = algorithm;

  if (
    !namedCurve ||
    !kNamedCurveAliases[namedCurve as keyof typeof kNamedCurveAliases]
  ) {
    throw lazyDOMException('Unrecognized namedCurve', 'NotSupportedError');
  }

  // Handle JWK format
  if (format === 'jwk') {
    const jwk = keyData as JWK;

    // Validate JWK
    if (jwk.kty !== 'EC') {
      throw lazyDOMException('Invalid JWK "kty" Parameter', 'DataError');
    }

    if (jwk.crv !== namedCurve) {
      throw lazyDOMException(
        'JWK "crv" does not match the requested algorithm',
        'DataError',
      );
    }

    // Check use parameter if present
    if (jwk.use !== undefined) {
      const expectedUse = name === 'ECDH' ? 'enc' : 'sig';
      if (jwk.use !== expectedUse) {
        throw lazyDOMException('Invalid JWK "use" Parameter', 'DataError');
      }
    }

    // Check alg parameter if present
    if (jwk.alg !== undefined) {
      let expectedAlg: string | undefined;

      if (name === 'ECDSA') {
        // Map namedCurve to expected ECDSA algorithm
        expectedAlg =
          namedCurve === 'P-256'
            ? 'ES256'
            : namedCurve === 'P-384'
              ? 'ES384'
              : namedCurve === 'P-521'
                ? 'ES512'
                : undefined;
      } else if (name === 'ECDH') {
        // ECDH uses ECDH-ES algorithm
        expectedAlg = 'ECDH-ES';
      }

      if (expectedAlg && jwk.alg !== undefined && jwk.alg !== expectedAlg) {
        throw lazyDOMException(
          'JWK "alg" does not match the requested algorithm',
          'DataError',
        );
      }
    }

    // Import using C++ layer
    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    const keyType = handle.initJwk(jwk, namedCurve as NamedCurve);

    if (keyType === undefined) {
      throw lazyDOMException('Invalid JWK', 'DataError');
    }

    // Create the appropriate KeyObject based on type
    let keyObject: KeyObject;
    if (keyType === 1) {
      keyObject = new PublicKeyObject(handle);
    } else if (keyType === 2) {
      keyObject = new PrivateKeyObject(handle);
    } else {
      throw lazyDOMException(
        'Unexpected key type from JWK import',
        'DataError',
      );
    }

    return new CryptoKey(keyObject, algorithm, keyUsages, extractable);
  }

  // Handle binary formats (spki, pkcs8, raw)
  if (format !== 'spki' && format !== 'pkcs8' && format !== 'raw') {
    throw lazyDOMException(
      `Unsupported format: ${format}`,
      'NotSupportedError',
    );
  }

  // Determine expected key type based on format
  const expectedKeyType =
    format === 'spki' || format === 'raw' ? 'public' : 'private';

  // Validate usages for the key type
  const isPublicKey = expectedKeyType === 'public';
  let validUsages: KeyUsage[];

  if (name === 'ECDSA') {
    validUsages = isPublicKey ? ['verify'] : ['sign'];
  } else if (name === 'ECDH') {
    validUsages = isPublicKey ? [] : ['deriveKey', 'deriveBits'];
  } else {
    throw lazyDOMException('Unsupported algorithm', 'NotSupportedError');
  }

  if (hasAnyNotIn(keyUsages, validUsages)) {
    throw lazyDOMException(
      `Unsupported key usage for a ${name} key`,
      'SyntaxError',
    );
  }

  // Convert keyData to ArrayBuffer
  const keyBuffer = bufferLikeToArrayBuffer(keyData as BufferLike);

  // Create KeyObject directly using the appropriate format
  let keyObject: KeyObject;

  if (format === 'raw') {
    // Raw format is only for public keys - use specialized EC raw import
    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    const curveAlias =
      kNamedCurveAliases[namedCurve as keyof typeof kNamedCurveAliases];
    // Only throw if initialization explicitly fails
    if (!handle.initECRaw(curveAlias, keyBuffer)) {
      throw lazyDOMException('Failed to import EC raw key', 'DataError');
    }
    keyObject = new PublicKeyObject(handle);
  } else {
    // Use standard DER import for spki/pkcs8
    keyObject = KeyObject.createKeyObject(
      expectedKeyType,
      keyBuffer,
      KFormatType.DER,
      format === 'spki' ? KeyEncoding.SPKI : KeyEncoding.PKCS8,
    );
  }

  return new CryptoKey(keyObject, algorithm, keyUsages, extractable);
}

// Node API
export const ecdsaSignVerify = (
  key: CryptoKey,
  data: BufferLike,
  { hash }: SubtleAlgorithm,
  signature?: BufferLike,
): ArrayBuffer | boolean => {
  const isSign = signature === undefined;
  const expectedKeyType = isSign ? 'private' : 'public';

  if (key.type !== expectedKeyType) {
    throw lazyDOMException(
      `Key must be a ${expectedKeyType} key`,
      'InvalidAccessError',
    );
  }

  const hashName = typeof hash === 'string' ? hash : hash?.name;

  if (!hashName) {
    throw lazyDOMException(
      'Hash algorithm is required for ECDSA',
      'InvalidAccessError',
    );
  }

  // Normalize hash algorithm name to WebCrypto format for C++ layer
  const normalizedHashName = normalizeHashName(hashName, HashContext.WebCrypto);

  // Create EC instance with the curve from the key
  const namedCurve = key.algorithm.namedCurve!;
  const ec = new Ec(namedCurve);

  // Extract and import the actual key data from the CryptoKey
  // Export in DER format with appropriate encoding
  const encoding =
    key.type === 'private' ? KeyEncoding.PKCS8 : KeyEncoding.SPKI;
  const keyData = key.keyObject.handle.exportKey(KFormatType.DER, encoding);
  const keyBuffer = bufferLikeToArrayBuffer(keyData);
  ec.native.importKey(
    'der',
    keyBuffer,
    key.algorithm.name!,
    key.extractable,
    key.usages,
  );

  const dataBuffer = bufferLikeToArrayBuffer(data);

  if (isSign) {
    // Sign operation
    return ec.native.sign(dataBuffer, normalizedHashName);
  } else {
    // Verify operation
    const signatureBuffer = bufferLikeToArrayBuffer(signature!);
    return ec.native.verify(dataBuffer, signatureBuffer, normalizedHashName);
  }
};

// WebCrypto API — only P-256, P-384, P-521 allowed per spec

export async function ec_generateKeyPair(
  name: string,
  namedCurve: string,
  extractable: boolean,
  keyUsages: KeyUsage[],
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _options?: KeyPairOptions, // TODO: Implement format options support
): Promise<CryptoKeyPair> {
  // validation checks
  if (!Object.keys(kNamedCurveAliases).includes(namedCurve || '')) {
    throw lazyDOMException(
      `Unrecognized namedCurve '${namedCurve}'`,
      'NotSupportedError',
    );
  }

  switch (name) {
    case 'ECDSA':
      if (hasAnyNotIn(keyUsages, ['sign', 'verify'])) {
        throw lazyDOMException(
          'Unsupported key usage for an ECDSA key',
          'SyntaxError',
        );
      }
      break;
    case 'ECDH':
      if (hasAnyNotIn(keyUsages, ['deriveKey', 'deriveBits'])) {
        throw lazyDOMException(
          'Unsupported key usage for an ECDH key',
          'SyntaxError',
        );
      }
    // Fall through
  }

  const ec = new Ec(namedCurve!);
  await ec.generateKeyPair();

  let publicUsages: KeyUsage[] = [];
  let privateUsages: KeyUsage[] = [];
  switch (name) {
    case 'ECDSA':
      publicUsages = getUsagesUnion(keyUsages, 'verify');
      privateUsages = getUsagesUnion(keyUsages, 'sign');
      break;
    case 'ECDH':
      publicUsages = [];
      privateUsages = getUsagesUnion(keyUsages, 'deriveKey', 'deriveBits');
      break;
  }

  const keyAlgorithm = { name, namedCurve: namedCurve! };

  // Export keys directly from the EC key pair using the internal EVP_PKEY
  // These methods export in DER format (SPKI for public, PKCS8 for private)
  const publicKeyData = ec.native.getPublicKey();
  const privateKeyData = ec.native.getPrivateKey();

  const pub = KeyObject.createKeyObject(
    'public',
    publicKeyData,
    KFormatType.DER,
    KeyEncoding.SPKI,
  ) as PublicKeyObject;
  const publicKey = new CryptoKey(
    pub,
    keyAlgorithm as SubtleAlgorithm,
    publicUsages,
    true,
  );

  // All keys are now exported in PKCS8 format for consistency
  const priv = KeyObject.createKeyObject(
    'private',
    privateKeyData,
    KFormatType.DER,
    KeyEncoding.PKCS8,
  ) as PrivateKeyObject;
  const privateKey = new CryptoKey(
    priv,
    keyAlgorithm as SubtleAlgorithm,
    privateUsages,
    extractable,
  );

  return { publicKey, privateKey };
}

function ec_prepareKeyGenParams(
  options: GenerateKeyPairOptions | undefined,
): Ec {
  if (!options) {
    throw new Error('Options are required for EC key generation');
  }

  const { namedCurve } = options as { namedCurve?: string };

  if (!namedCurve) {
    throw new Error('namedCurve is required for EC key generation');
  }

  return new Ec(namedCurve);
}

function ec_formatKeyPairOutput(
  ec: Ec,
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

  const publicKeyData = ec.native.getPublicKey();
  const privateKeyData = ec.native.getPrivateKey();

  const pub = KeyObject.createKeyObject(
    'public',
    publicKeyData,
    KFormatType.DER,
    KeyEncoding.SPKI,
  ) as PublicKeyObject;

  const priv = KeyObject.createKeyObject(
    'private',
    privateKeyData,
    KFormatType.DER,
    KeyEncoding.PKCS8,
  ) as PrivateKeyObject;

  let publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
  let privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;

  if (publicFormat === -1) {
    publicKey = pub;
  } else {
    const format =
      publicFormat === KFormatType.PEM ? KFormatType.PEM : KFormatType.DER;
    const keyEncoding =
      publicType === KeyEncoding.SPKI ? KeyEncoding.SPKI : KeyEncoding.SPKI;
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
      privateType === KeyEncoding.PKCS8
        ? KeyEncoding.PKCS8
        : privateType === KeyEncoding.SEC1
          ? KeyEncoding.SEC1
          : KeyEncoding.PKCS8;
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

export async function ec_generateKeyPairNode(
  options: GenerateKeyPairOptions | undefined,
  encoding: KeyPairGenConfig,
): Promise<{
  publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
  privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;
}> {
  const ec = ec_prepareKeyGenParams(options);
  await ec.generateKeyPair();
  return ec_formatKeyPairOutput(ec, encoding);
}

export function ec_generateKeyPairNodeSync(
  options: GenerateKeyPairOptions | undefined,
  encoding: KeyPairGenConfig,
): {
  publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
  privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;
} {
  const ec = ec_prepareKeyGenParams(options);
  ec.generateKeyPairSync();
  return ec_formatKeyPairOutput(ec, encoding);
}

export function ecDeriveBits(
  algorithm: SubtleAlgorithm,
  baseKey: CryptoKey,
  length: number | null,
): ArrayBuffer {
  const publicKey = algorithm.public;

  if (!publicKey) {
    throw new Error('Public key is required for ECDH derivation');
  }

  if (baseKey.algorithm.name !== publicKey.algorithm.name) {
    throw new Error('Keys must be of the same algorithm');
  }

  if (baseKey.algorithm.namedCurve !== publicKey.algorithm.namedCurve) {
    throw new Error('Keys must use the same curve');
  }

  const namedCurve = baseKey.algorithm.namedCurve;
  if (!namedCurve) {
    throw new Error('Curve name is missing');
  }

  const opensslCurve =
    kNamedCurveAliases[namedCurve as keyof typeof kNamedCurveAliases];
  const ecdh = new ECDH(opensslCurve);

  const jwkPrivate = baseKey.keyObject.handle.exportJwk({}, false);
  if (!jwkPrivate.d) throw new Error('Invalid private key');
  const privateBytes = Buffer.from(jwkPrivate.d, 'base64');
  ecdh.setPrivateKey(privateBytes);

  const jwkPublic = publicKey.keyObject.handle.exportJwk({}, false);
  if (!jwkPublic.x || !jwkPublic.y) throw new Error('Invalid public key');
  const x = Buffer.from(jwkPublic.x, 'base64');
  const y = Buffer.from(jwkPublic.y, 'base64');
  const publicBytes = Buffer.concat([Buffer.from([0x04]), x, y]);

  const secret = ecdh.computeSecret(publicBytes);
  const secretBuf = Buffer.from(secret);

  // If length is null, return full secret
  if (length === null) {
    return secretBuf.buffer;
  }

  // If length is specified, truncate
  const byteLength = Math.ceil(length / 8);
  if (secretBuf.byteLength >= byteLength) {
    return secretBuf.subarray(0, byteLength).buffer as ArrayBuffer;
  }

  throw new Error('Derived key is shorter than requested length');
}
