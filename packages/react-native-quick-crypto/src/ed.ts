import { NitroModules } from 'react-native-nitro-modules';
import { AsymmetricKeyObject, PrivateKeyObject, PublicKeyObject } from './keys';
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
    switch (
      (options.privateKey as AsymmetricKeyObject).asymmetricKeyType as string
    ) {
      case 'dh':
      case 'ed':
        throw new Error(`'${this.type}' is not implemented`);
      case 'x25519':
      case 'x448':
        break;
      default:
        throw new Error(`Unknown curve type: ${this.type}`);
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
  checkDiffieHellmanOptions(options);
  const privateKey = options.privateKey as PrivateKeyObject;
  const type = privateKey.asymmetricKeyType as CFRGKeyPairType;
  const ed = new Ed(type, {});
  ed.diffieHellman(options, callback);
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
  } catch (e: unknown) {
    err = e as Error;
  }

  if (callback) {
    callback(err, ed.getPublicKey(), ed.getPrivateKey());
    return;
  }
  return [err, ed.getPublicKey(), ed.getPrivateKey()];
}

function checkDiffieHellmanOptions(options: DiffieHellmanOptions): void {
  const { privateKey, publicKey } = options;

  // instance checks
  if (!(privateKey instanceof PrivateKeyObject)) {
    throw new Error('privateKey must be a PrivateKeyObject');
  }
  if (!(publicKey instanceof PublicKeyObject)) {
    throw new Error('publicKey must be a PublicKeyObject');
  }

  // type checks
  if (privateKey.type !== 'private') {
    throw new Error('privateKey must be a private KeyObject');
  }
  if (publicKey.type !== 'public') {
    throw new Error('publicKey must be a public KeyObject');
  }

  // key types must match
  if (
    privateKey.asymmetricKeyType &&
    publicKey.asymmetricKeyType &&
    privateKey.asymmetricKeyType !== publicKey.asymmetricKeyType
  ) {
    throw new Error('Keys must be asymmetric and their types must match');
  }

  switch (privateKey.asymmetricKeyType) {
    // case 'dh': // TODO: uncomment when implemented
    // case 'ec': // TODO: uncomment when implemented
    case 'x25519':
    case 'x448':
      break;
    default:
      throw new Error(`Unknown curve type: ${privateKey.asymmetricKeyType}`);
  }
}
