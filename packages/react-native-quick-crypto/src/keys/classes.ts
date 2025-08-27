import { Buffer } from 'buffer';
import { NitroModules } from 'react-native-nitro-modules';
import type {
  AsymmetricKeyType,
  EncodingOptions,
  KeyObjectHandle,
  KeyUsage,
  SubtleAlgorithm,
} from '../utils';
import { KeyType } from '../utils';
import { parsePrivateKeyEncoding, parsePublicKeyEncoding } from './utils';

export class CryptoKey {
  keyObject: KeyObject;
  keyAlgorithm: SubtleAlgorithm;
  keyUsages: KeyUsage[];
  keyExtractable: boolean;

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
  export(options: { format: 'pem' } & EncodingOptions): string | Buffer;
  export(options?: { format: 'der' } & EncodingOptions): Buffer;
  export(options?: { format: 'jwk' } & EncodingOptions): never;
  export(options?: EncodingOptions): string | Buffer;
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  export(_options?: EncodingOptions): string | Buffer {
    // This is a placeholder and should be overridden by subclasses.
    throw new Error('export() must be implemented by subclasses');
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

  // static from(key) {
  //   if (!isCryptoKey(key))
  //     throw new ERR_INVALID_ARG_TYPE('key', 'CryptoKey', key);
  //   return key[kKeyObject];
  // }

  static createKeyObject(type: string, key: ArrayBuffer): KeyObject {
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
    handle.init(keyType, key);

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

    // Return regular KeyObject for symmetric keys or if asymmetric detection failed
    return new KeyObject(type, handle);
  }

  equals(otherKeyObject: unknown): boolean {
    if (!(otherKeyObject instanceof KeyObject)) {
      throw new TypeError(
        `Invalid argument type for "otherKeyObject", expected "KeyObject" but got ${typeof otherKeyObject}`,
      );
    }

    return (
      this.type === otherKeyObject.type &&
      this.handle.equals(otherKeyObject.handle)
    );
  }
}

export class SecretKeyObject extends KeyObject {
  constructor(handle: KeyObjectHandle) {
    super('secret', handle);
  }

  // get symmetricKeySize() {
  //   return this[kHandle].getSymmetricKeySize();
  // }

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
    return Buffer.from(key);
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

  // get asymmetricKeyDetails() {
  //   switch (this._asymmetricKeyType) {
  //     case 'rsa':
  //     case 'rsa-pss':
  //     case 'dsa':
  //     case 'ec':
  //       return (
  //         this[kAsymmetricKeyDetails] ||
  //         (this[kAsymmetricKeyDetails] = normalizeKeyDetails(
  //           this[kHandle].keyDetail({})
  //         ))
  //       );
  //     default:
  //       return {};
  //   }
  // }
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
