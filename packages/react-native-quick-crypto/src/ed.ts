import { NitroModules } from 'react-native-nitro-modules';
import { Buffer } from '@craftzdog/react-native-buffer';
import { AsymmetricKeyObject, PrivateKeyObject } from './keys';
import type { EdKeyPair } from './specs/edKeyPair.nitro';
import type {
  BinaryLike,
  CFRGKeyPairType,
  DiffieHellmanCallback,
  DiffieHellmanOptions,
  GenerateKeyPairCallback,
  GenerateKeyPairReturn,
  Hex,
  KeyPairGenConfig,
  KeyPairType,
} from './utils';
import { binaryLikeToArrayBuffer as toAB } from './utils';

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
    checkDiffieHellmanOptions(options);

    // key types must be of certain type
    const keyType = (options.privateKey as AsymmetricKeyObject)
      .asymmetricKeyType;
    switch (keyType) {
      case 'x25519':
      case 'x448':
        break;
      default:
        throw new Error(`Unsupported or unimplemented curve type: ${keyType}`);
    }

    // extract the private and public keys as ArrayBuffers
    const privateKey = toAB(options.privateKey);
    const publicKey = toAB(options.publicKey);

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
    this.native.generateKeyPair(
      this.config.publicFormat || (-1 as number),
      this.config.publicType || (-1 as number),
      this.config.privateFormat || (-1 as number),
      this.config.privateType || (-1 as number),
      this.config.cipher as string,
      this.config.passphrase as ArrayBuffer,
    );
  }

  generateKeyPairSync(): void {
    this.native.generateKeyPairSync(
      this.config.publicFormat || (-1 as number),
      this.config.publicType || (-1 as number),
      this.config.privateFormat || (-1 as number),
      this.config.privateType || (-1 as number),
      this.config.cipher as string,
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
  const privateKey = options.privateKey as PrivateKeyObject;
  const type = privateKey.asymmetricKeyType as CFRGKeyPairType;
  const ed = new Ed(type, {});
  return ed.diffieHellman(options, callback);
}

// Node API
export function ed_generateKeyPair(
  isAsync: boolean,
  type: KeyPairType,
  encoding: KeyPairGenConfig,
  callback: GenerateKeyPairCallback | undefined,
): GenerateKeyPairReturn | void {
  const ed = new Ed(type, encoding);

  // Async path
  if (isAsync) {
    if (!callback) {
      // This should not happen if called from public API
      throw new Error('A callback is required for async key generation.');
    }
    ed.generateKeyPair()
      .then(() => {
        callback(undefined, ed.getPublicKey(), ed.getPrivateKey());
      })
      .catch(err => {
        callback(err, undefined, undefined);
      });
    return;
  }

  // Sync path
  let err: Error | undefined;
  try {
    ed.generateKeyPairSync();
  } catch (e) {
    err = e instanceof Error ? e : new Error(String(e));
  }

  if (callback) {
    callback(err, ed.getPublicKey(), ed.getPrivateKey());
    return;
  }
  return [err, ed.getPublicKey(), ed.getPrivateKey()];
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
    case 'x25519':
    case 'x448':
      break;
    default:
      throw new Error(
        `Unknown curve type: ${privateKeyAsym.asymmetricKeyType}`,
      );
  }
}
