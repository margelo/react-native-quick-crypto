import { NitroModules } from 'react-native-nitro-modules';
import { Buffer } from '@craftzdog/react-native-buffer';
import type { AsymmetricKeyObject, PrivateKeyObject } from './keys/classes';
import {
  CryptoKey,
  KeyObject,
  PublicKeyObject,
  PrivateKeyObject as PrivateKeyObjectClass,
} from './keys/classes';
import type { EdKeyPair } from './specs/edKeyPair.nitro';
import type {
  BinaryLike,
  CFRGKeyPairType,
  CryptoKeyPair,
  DiffieHellmanCallback,
  DiffieHellmanOptions,
  GenerateKeyPairCallback,
  GenerateKeyPairReturn,
  Hex,
  KeyPairGenConfig,
  KeyUsage,
  SubtleAlgorithm,
} from './utils';
import {
  binaryLikeToArrayBuffer as toAB,
  hasAnyNotIn,
  lazyDOMException,
  getUsagesUnion,
  KFormatType,
  KeyEncoding,
} from './utils';
import { ECDH } from './ecdh';

export class Ed {
  type: CFRGKeyPairType;
  config: KeyPairGenConfig;
  native: EdKeyPair;

  constructor(type: CFRGKeyPairType, config: KeyPairGenConfig) {
    this.type = type;
    this.config = config;
    this.native = NitroModules.createHybridObject<EdKeyPair>('EdKeyPair');
    this.native.setCurve(type);
  }

  /**
   * Computes the Diffie-Hellman secret based on a privateKey and a publicKey.
   * Both keys must have the same asymmetricKeyType, which must be one of 'dh'
   * (for Diffie-Hellman), 'ec', 'x448', or 'x25519' (for ECDH).
   *
   * @api nodejs/node
   *
   * @param options `{ privateKey, publicKey }`, both of which are `KeyObject`s
   * @param callback optional `(err, secret) => void`
   * @returns `Buffer` if no callback, or `void` if callback is provided
   */
  diffieHellman(
    options: DiffieHellmanOptions,
    callback?: DiffieHellmanCallback,
  ): Buffer | void {
    // extract raw key bytes from KeyObject instances
    const privKeyObj = options.privateKey as AsymmetricKeyObject;
    const pubKeyObj = options.publicKey as AsymmetricKeyObject;
    const privateKey = privKeyObj.handle.exportKey();
    const publicKey = pubKeyObj.handle.exportKey();

    try {
      const ret = this.native.diffieHellman(privateKey, publicKey);
      if (!ret) {
        throw new Error('No secret');
      }
      if (callback) {
        callback(null, Buffer.from(ret));
      } else {
        return Buffer.from(ret);
      }
    } catch (e: unknown) {
      const err = e as Error;
      if (callback) {
        callback(err, undefined);
      } else {
        throw err;
      }
    }
  }

  async generateKeyPair(): Promise<void> {
    await this.native.generateKeyPair(
      this.config.publicFormat ?? -1,
      this.config.publicType ?? -1,
      this.config.privateFormat ?? -1,
      this.config.privateType ?? -1,
      this.config.cipher,
      this.config.passphrase as ArrayBuffer,
    );
  }

  generateKeyPairSync(): void {
    this.native.generateKeyPairSync(
      this.config.publicFormat ?? -1,
      this.config.publicType ?? -1,
      this.config.privateFormat ?? -1,
      this.config.privateType ?? -1,
      this.config.cipher,
      this.config.passphrase as ArrayBuffer,
    );
  }

  getPublicKey(): ArrayBuffer {
    return this.native.getPublicKey();
  }

  getPrivateKey(): ArrayBuffer {
    return this.native.getPrivateKey();
  }

  /**
   * Computes the Diffie-Hellman shared secret based on a privateKey and a
   * publicKey for key exchange
   *
   * @api \@paulmillr/noble-curves/ed25519
   *
   * @param privateKey
   * @param publicKey
   * @returns shared secret key
   */
  getSharedSecret(privateKey: Hex, publicKey: Hex): ArrayBuffer {
    return this.native.diffieHellman(toAB(privateKey), toAB(publicKey));
  }

  async sign(message: BinaryLike, key?: BinaryLike): Promise<ArrayBuffer> {
    return key
      ? this.native.sign(toAB(message), toAB(key))
      : this.native.sign(toAB(message));
  }

  signSync(message: BinaryLike, key?: BinaryLike): ArrayBuffer {
    return key
      ? this.native.signSync(toAB(message), toAB(key))
      : this.native.signSync(toAB(message));
  }

  async verify(
    signature: BinaryLike,
    message: BinaryLike,
    key?: BinaryLike,
  ): Promise<boolean> {
    return key
      ? this.native.verify(toAB(signature), toAB(message), toAB(key))
      : this.native.verify(toAB(signature), toAB(message));
  }

  verifySync(
    signature: BinaryLike,
    message: BinaryLike,
    key?: BinaryLike,
  ): boolean {
    return key
      ? this.native.verifySync(toAB(signature), toAB(message), toAB(key))
      : this.native.verifySync(toAB(signature), toAB(message));
  }
}

// Node API
export function diffieHellman(
  options: DiffieHellmanOptions,
  callback?: DiffieHellmanCallback,
): Buffer | void {
  checkDiffieHellmanOptions(options);

  const privateKey = options.privateKey as PrivateKeyObject;
  const keyType = privateKey.asymmetricKeyType;

  if (keyType === 'ec') {
    return ecDiffieHellman(options, callback);
  }

  const type = keyType as CFRGKeyPairType;
  const ed = new Ed(type, {});
  return ed.diffieHellman(options, callback);
}

function ed_createKeyObjects(ed: Ed): {
  pub: PublicKeyObject;
  priv: PrivateKeyObjectClass;
} {
  const publicKeyData = ed.getPublicKey();
  const privateKeyData = ed.getPrivateKey();
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
  ) as PrivateKeyObjectClass;
  return { pub, priv };
}

// Node API
function ed_formatKeyPairOutput(
  ed: Ed,
  encoding: KeyPairGenConfig,
): {
  publicKey: PublicKeyObject | string | ArrayBuffer;
  privateKey: PrivateKeyObjectClass | string | ArrayBuffer;
} {
  const { publicFormat, privateFormat, cipher, passphrase } = encoding;
  const { pub, priv } = ed_createKeyObjects(ed);

  let publicKey: PublicKeyObject | string | ArrayBuffer;
  let privateKey: PrivateKeyObjectClass | string | ArrayBuffer;

  if (publicFormat == null || publicFormat === -1) {
    publicKey = pub;
  } else {
    const format =
      publicFormat === KFormatType.PEM ? KFormatType.PEM : KFormatType.DER;
    const exported = pub.handle.exportKey(format, KeyEncoding.SPKI);
    if (format === KFormatType.PEM) {
      publicKey = Buffer.from(new Uint8Array(exported)).toString('utf-8');
    } else {
      publicKey = exported;
    }
  }

  if (privateFormat == null || privateFormat === -1) {
    privateKey = priv;
  } else {
    const format =
      privateFormat === KFormatType.PEM ? KFormatType.PEM : KFormatType.DER;
    const exported = priv.handle.exportKey(
      format,
      KeyEncoding.PKCS8,
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

export function ed_generateKeyPair(
  isAsync: boolean,
  type: CFRGKeyPairType,
  encoding: KeyPairGenConfig,
  callback: GenerateKeyPairCallback | undefined,
): GenerateKeyPairReturn | void {
  const derConfig: KeyPairGenConfig = {
    ...encoding,
    publicFormat: KFormatType.DER,
    publicType: KeyEncoding.SPKI,
    privateFormat: KFormatType.DER,
    privateType: KeyEncoding.PKCS8,
  };
  const ed = new Ed(type, derConfig);

  if (isAsync) {
    if (!callback) {
      throw new Error('A callback is required for async key generation.');
    }
    ed.generateKeyPair()
      .then(() => {
        const { publicKey, privateKey } = ed_formatKeyPairOutput(ed, encoding);
        callback(undefined, publicKey, privateKey);
      })
      .catch(err => {
        callback(err, undefined, undefined);
      });
    return;
  }

  let err: Error | undefined;
  try {
    ed.generateKeyPairSync();
  } catch (e) {
    err = e instanceof Error ? e : new Error(String(e));
  }

  const { publicKey, privateKey } = err
    ? { publicKey: undefined, privateKey: undefined }
    : ed_formatKeyPairOutput(ed, encoding);

  if (callback) {
    callback(err, publicKey, privateKey);
    return;
  }
  return [err, publicKey, privateKey];
}

function ecDiffieHellman(
  options: DiffieHellmanOptions,
  callback?: DiffieHellmanCallback,
): Buffer | void {
  const privateKey = options.privateKey as PrivateKeyObject;
  const publicKey = options.publicKey as AsymmetricKeyObject;

  const curveName = privateKey.namedCurve;
  if (!curveName) {
    throw new Error('Unable to determine EC curve name from private key');
  }

  const ecdh = new ECDH(curveName);

  const jwkPrivate = privateKey.handle.exportJwk({}, false);
  if (!jwkPrivate.d) throw new Error('Invalid private key');
  ecdh.setPrivateKey(Buffer.from(jwkPrivate.d, 'base64url'));

  const jwkPublic = publicKey.handle.exportJwk({}, false);
  if (!jwkPublic.x || !jwkPublic.y) throw new Error('Invalid public key');
  const x = Buffer.from(jwkPublic.x, 'base64url');
  const y = Buffer.from(jwkPublic.y, 'base64url');
  const publicBytes = Buffer.concat([Buffer.from([0x04]), x, y]);

  try {
    const secret = ecdh.computeSecret(publicBytes);
    if (callback) {
      callback(null, secret);
    } else {
      return secret;
    }
  } catch (e: unknown) {
    const err = e as Error;
    if (callback) {
      callback(err, undefined);
    } else {
      throw err;
    }
  }
}

function checkDiffieHellmanOptions(options: DiffieHellmanOptions): void {
  const { privateKey, publicKey } = options;

  // Check if keys are KeyObject instances
  if (
    !privateKey ||
    typeof privateKey !== 'object' ||
    !('type' in privateKey)
  ) {
    throw new Error('privateKey must be a KeyObject');
  }
  if (!publicKey || typeof publicKey !== 'object' || !('type' in publicKey)) {
    throw new Error('publicKey must be a KeyObject');
  }

  // type checks
  if (privateKey.type !== 'private') {
    throw new Error('privateKey must be a private KeyObject');
  }
  if (publicKey.type !== 'public') {
    throw new Error('publicKey must be a public KeyObject');
  }

  // For asymmetric keys, check if they have the asymmetricKeyType property
  const privateKeyAsym = privateKey as AsymmetricKeyObject;
  const publicKeyAsym = publicKey as AsymmetricKeyObject;

  // key types must match
  if (
    privateKeyAsym.asymmetricKeyType &&
    publicKeyAsym.asymmetricKeyType &&
    privateKeyAsym.asymmetricKeyType !== publicKeyAsym.asymmetricKeyType
  ) {
    throw new Error('Keys must be asymmetric and their types must match');
  }

  switch (privateKeyAsym.asymmetricKeyType) {
    // case 'dh': // TODO: uncomment when implemented
    case 'ec': {
      const privateCurve = privateKeyAsym.namedCurve;
      const publicCurve = publicKeyAsym.namedCurve;
      if (privateCurve && publicCurve && privateCurve !== publicCurve) {
        throw new Error('Private and public key curves do not match');
      }
      break;
    }
    case 'x25519':
    case 'x448':
      break;
    default:
      throw new Error(
        `Unknown curve type: ${privateKeyAsym.asymmetricKeyType}`,
      );
  }
}

export async function ed_generateKeyPairWebCrypto(
  type: 'ed25519' | 'ed448',
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKeyPair> {
  if (hasAnyNotIn(keyUsages, ['sign', 'verify'])) {
    throw lazyDOMException(`Unsupported key usage for ${type}`, 'SyntaxError');
  }

  const publicUsages = getUsagesUnion(keyUsages, 'verify');
  const privateUsages = getUsagesUnion(keyUsages, 'sign');

  if (privateUsages.length === 0) {
    throw lazyDOMException('Usages cannot be empty', 'SyntaxError');
  }

  // Request DER-encoded SPKI for public key, PKCS8 for private key
  const config = {
    publicFormat: KFormatType.DER,
    publicType: KeyEncoding.SPKI,
    privateFormat: KFormatType.DER,
    privateType: KeyEncoding.PKCS8,
  };
  const ed = new Ed(type, config);
  await ed.generateKeyPair();

  const algorithmName = type === 'ed25519' ? 'Ed25519' : 'Ed448';
  const { pub, priv } = ed_createKeyObjects(ed);

  const publicKey = new CryptoKey(
    pub,
    { name: algorithmName } as SubtleAlgorithm,
    publicUsages,
    true,
  );
  const privateKey = new CryptoKey(
    priv,
    { name: algorithmName } as SubtleAlgorithm,
    privateUsages,
    extractable,
  );

  return { publicKey, privateKey };
}

export async function x_generateKeyPairWebCrypto(
  type: 'x25519' | 'x448',
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKeyPair> {
  if (hasAnyNotIn(keyUsages, ['deriveKey', 'deriveBits'])) {
    throw lazyDOMException(`Unsupported key usage for ${type}`, 'SyntaxError');
  }

  const publicUsages = getUsagesUnion(keyUsages);
  const privateUsages = getUsagesUnion(keyUsages, 'deriveKey', 'deriveBits');

  if (privateUsages.length === 0) {
    throw lazyDOMException('Usages cannot be empty', 'SyntaxError');
  }

  // Request DER-encoded SPKI for public key, PKCS8 for private key
  const config = {
    publicFormat: KFormatType.DER,
    publicType: KeyEncoding.SPKI,
    privateFormat: KFormatType.DER,
    privateType: KeyEncoding.PKCS8,
  };
  const ed = new Ed(type, config);
  await ed.generateKeyPair();

  const algorithmName = type === 'x25519' ? 'X25519' : 'X448';
  const { pub, priv } = ed_createKeyObjects(ed);

  const publicKey = new CryptoKey(
    pub,
    { name: algorithmName } as SubtleAlgorithm,
    publicUsages,
    true,
  );
  const privateKey = new CryptoKey(
    priv,
    { name: algorithmName } as SubtleAlgorithm,
    privateUsages,
    extractable,
  );

  return { publicKey, privateKey };
}

export function xDeriveBits(
  algorithm: SubtleAlgorithm,
  baseKey: CryptoKey,
  length: number | null,
): ArrayBuffer {
  const publicKey = algorithm.public;

  if (!publicKey) {
    throw new Error('Public key is required for X25519/X448 derivation');
  }

  if (baseKey.algorithm.name !== publicKey.algorithm.name) {
    throw new Error('Keys must be of the same algorithm');
  }

  const type = baseKey.algorithm.name.toLowerCase() as 'x25519' | 'x448';
  const ed = new Ed(type, {});

  // Export raw keys
  const privateKeyBytes = baseKey.keyObject.handle.exportKey();
  const publicKeyBytes = publicKey.keyObject.handle.exportKey();

  const privateKeyTyped = new Uint8Array(privateKeyBytes);
  const publicKeyTyped = new Uint8Array(publicKeyBytes);

  const secret = ed.getSharedSecret(privateKeyTyped, publicKeyTyped);

  // If length is null, return the full secret
  if (length === null) {
    return secret;
  }

  // If length is specified, truncate
  const byteLength = Math.ceil(length / 8);
  if (secret.byteLength >= byteLength) {
    return secret.slice(0, byteLength);
  }

  throw new Error('Derived key is shorter than requested length');
}
