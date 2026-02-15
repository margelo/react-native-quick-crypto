import { Buffer } from 'buffer';
import { NitroModules } from 'react-native-nitro-modules';
import type {
  AsymmetricKeyType,
  EncodingOptions,
  KeyDetail,
  KeyObjectHandle,
  KeyUsage,
  SubtleAlgorithm,
} from '../utils';
import { KeyType, KFormatType, KeyEncoding } from '../utils';
import { parsePrivateKeyEncoding, parsePublicKeyEncoding } from './utils';

export class CryptoKey {
  keyObject: KeyObject;
  keyAlgorithm: SubtleAlgorithm;
  keyUsages: KeyUsage[];
  keyExtractable: boolean;

  get [Symbol.toStringTag](): string {
    return 'CryptoKey';
  }

  constructor(
    keyObject: KeyObject,
    keyAlgorithm: SubtleAlgorithm,
    keyUsages: KeyUsage[],
    keyExtractable: boolean,
  ) {
    this.keyObject = keyObject;
    this.keyAlgorithm = keyAlgorithm;
    this.keyUsages = keyUsages;
    this.keyExtractable = keyExtractable;
  }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  inspect(_depth: number, _options: unknown): unknown {
    throw new Error('CryptoKey.inspect is not implemented');
    // if (depth < 0) return this;

    // const opts = {
    //   ...options,
    //   depth: options.depth == null ? null : options.depth - 1,
    // };

    // return `CryptoKey ${inspect(
    //   {
    //     type: this.type,
    //     extractable: this.extractable,
    //     algorithm: this.algorithm,
    //     usages: this.usages,
    //   },
    //   opts
    // )}`;
  }

  get type() {
    // if (!(this instanceof CryptoKey)) throw new Error('Invalid CryptoKey');
    return this.keyObject.type;
  }

  get extractable() {
    return this.keyExtractable;
  }

  get algorithm() {
    return this.keyAlgorithm;
  }

  get usages() {
    return this.keyUsages;
  }
}

export class KeyObject {
  handle: KeyObjectHandle;
  type: 'public' | 'secret' | 'private';

  get [Symbol.toStringTag](): string {
    return 'KeyObject';
  }

  export(options: { format: 'pem' } & EncodingOptions): string | Buffer;
  export(options?: { format: 'der' } & EncodingOptions): Buffer;
  export(options?: { format: 'jwk' } & EncodingOptions): never;
  export(options?: EncodingOptions): string | Buffer;
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  export(_options?: EncodingOptions): string | Buffer {
    // This is a placeholder and should be overridden by subclasses.
    throw new Error('export() must be implemented by subclasses');
  }

  equals(otherKeyObject: KeyObject): boolean {
    if (!(otherKeyObject instanceof KeyObject)) {
      throw new TypeError('otherKeyObject must be a KeyObject');
    }
    return this.handle.keyEquals(otherKeyObject.handle);
  }

  constructor(type: string, handle: KeyObjectHandle);
  constructor(type: string, key: ArrayBuffer);
  constructor(type: string, handleOrKey: KeyObjectHandle | ArrayBuffer) {
    if (type !== 'secret' && type !== 'public' && type !== 'private')
      throw new Error(`invalid KeyObject type: ${type}`);

    if (handleOrKey instanceof ArrayBuffer) {
      this.handle = NitroModules.createHybridObject('KeyObjectHandle');
      let keyType: KeyType;
      switch (type) {
        case 'public':
          keyType = KeyType.PUBLIC;
          break;
        case 'private':
          keyType = KeyType.PRIVATE;
          break;
        case 'secret':
          keyType = KeyType.SECRET;
          break;
        default:
          // Should not happen
          throw new Error('invalid key type');
      }
      this.handle.init(keyType, handleOrKey);
    } else {
      this.handle = handleOrKey;
    }
    this.type = type as 'public' | 'secret' | 'private';
  }

  static from(key: CryptoKey): KeyObject {
    if (!(key instanceof CryptoKey)) {
      throw new TypeError(
        `The "key" argument must be an instance of CryptoKey. Received ${typeof key}`,
      );
    }
    return key.keyObject;
  }

  toCryptoKey(
    algorithm: SubtleAlgorithm,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): CryptoKey {
    return new CryptoKey(this, algorithm, keyUsages, extractable);
  }

  static createKeyObject(
    type: string,
    key: ArrayBuffer,
    format?: KFormatType,
    encoding?: KeyEncoding,
  ): KeyObject {
    if (type !== 'secret' && type !== 'public' && type !== 'private')
      throw new Error(`invalid KeyObject type: ${type}`);

    const handle = NitroModules.createHybridObject(
      'KeyObjectHandle',
    ) as KeyObjectHandle;
    let keyType: KeyType;
    switch (type) {
      case 'public':
        keyType = KeyType.PUBLIC;
        break;
      case 'private':
        keyType = KeyType.PRIVATE;
        break;
      case 'secret':
        keyType = KeyType.SECRET;
        break;
      default:
        throw new Error('invalid key type');
    }

    // If format is provided, use it (encoding is optional)
    if (format !== undefined) {
      handle.init(keyType, key, format, encoding);
    } else {
      handle.init(keyType, key);
    }

    // For asymmetric keys, return the appropriate subclass
    if (type === 'public' || type === 'private') {
      try {
        handle.getAsymmetricKeyType();
        // If we get here, it's an asymmetric key - return the appropriate subclass
        if (type === 'public') {
          return new PublicKeyObject(handle);
        } else {
          return new PrivateKeyObject(handle);
        }
      } catch {
        // Not an asymmetric key, fall through to regular KeyObject
      }
    }

    // For secret keys, return SecretKeyObject
    if (type === 'secret') {
      return new SecretKeyObject(handle);
    }

    // Return regular KeyObject for symmetric keys or if asymmetric detection failed
    return new KeyObject(type, handle);
  }

  getAsymmetricKeyType(): undefined {
    return undefined;
  }

  getAsymmetricKeyDetails(): undefined {
    return undefined;
  }
}

export class SecretKeyObject extends KeyObject {
  constructor(handle: KeyObjectHandle) {
    super('secret', handle);
  }

  get symmetricKeySize(): number {
    return this.handle.getSymmetricKeySize();
  }

  export(options: { format: 'pem' } & EncodingOptions): never;
  export(options: { format: 'der' } & EncodingOptions): Buffer;
  export(options: { format: 'jwk' } & EncodingOptions): never;
  export(options?: EncodingOptions): Buffer;
  export(options?: EncodingOptions): Buffer {
    if (options?.format === 'pem' || options?.format === 'jwk') {
      throw new Error(
        `SecretKey export for ${options.format} is not supported`,
      );
    }
    const key = this.handle.exportKey();
    return Buffer.from(new Uint8Array(key));
  }
}

// const kAsymmetricKeyType = Symbol('kAsymmetricKeyType');
// const kAsymmetricKeyDetails = Symbol('kAsymmetricKeyDetails');

// function normalizeKeyDetails(details = {}) {
//   if (details.publicExponent !== undefined) {
//     return {
//       ...details,
//       publicExponent: bigIntArrayToUnsignedBigInt(
//         new Uint8Array(details.publicExponent)
//       ),
//     };
//   }
//   return details;
// }

export class AsymmetricKeyObject extends KeyObject {
  constructor(type: string, handle: KeyObjectHandle) {
    super(type, handle);
  }

  private _asymmetricKeyType?: AsymmetricKeyType;

  get asymmetricKeyType(): AsymmetricKeyType {
    if (!this._asymmetricKeyType) {
      this._asymmetricKeyType = this.handle.getAsymmetricKeyType();
    }
    return this._asymmetricKeyType;
  }

  private _asymmetricKeyDetails?: KeyDetail;

  get asymmetricKeyDetails() {
    if (!this._asymmetricKeyDetails) {
      this._asymmetricKeyDetails = this.handle.keyDetail();
    }
    return this._asymmetricKeyDetails;
  }

  get namedCurve(): string | undefined {
    return this.asymmetricKeyDetails?.namedCurve;
  }
}

export class PublicKeyObject extends AsymmetricKeyObject {
  constructor(handle: KeyObjectHandle) {
    super('public', handle);
  }

  export(options: { format: 'pem' } & EncodingOptions): string;
  export(options: { format: 'der' } & EncodingOptions): Buffer;
  export(options: { format: 'jwk' } & EncodingOptions): never;
  export(options: EncodingOptions): string | Buffer {
    if (options?.format === 'jwk') {
      throw new Error('PublicKey export for jwk is not implemented');
    }
    const { format, type } = parsePublicKeyEncoding(
      options,
      this.asymmetricKeyType,
    );
    const key = this.handle.exportKey(format, type);
    const buffer = Buffer.from(key);
    if (options?.format === 'pem') {
      return buffer.toString('utf-8');
    }
    return buffer;
  }
}

export class PrivateKeyObject extends AsymmetricKeyObject {
  constructor(handle: KeyObjectHandle) {
    super('private', handle);
  }

  export(options: { format: 'pem' } & EncodingOptions): string;
  export(options: { format: 'der' } & EncodingOptions): Buffer;
  export(options: { format: 'jwk' } & EncodingOptions): never;
  export(options: EncodingOptions): string | Buffer {
    if (options?.format === 'jwk') {
      if (options.passphrase !== undefined) {
        throw new Error('jwk does not support encryption');
      }
      throw new Error('PrivateKey export for jwk is not implemented');
    }
    const { format, type, cipher, passphrase } = parsePrivateKeyEncoding(
      options,
      this.asymmetricKeyType,
    );
    const key = this.handle.exportKey(format, type, cipher, passphrase);
    const buffer = Buffer.from(key);
    if (options?.format === 'pem') {
      return buffer.toString('utf-8');
    }
    return buffer;
  }
}
