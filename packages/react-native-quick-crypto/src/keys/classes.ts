import type { KeyObjectHandle } from '../specs/keyObjectHandle.nitro';
import type {
  AsymmetricKeyType,
  EncodingOptions,
  KeyUsage,
  SubtleAlgorithm,
} from '../utils';
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
  type: 'public' | 'secret' | 'private' | 'unknown' = 'unknown';
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  export(_options?: EncodingOptions): ArrayBuffer {
    return new ArrayBuffer(0);
  }

  constructor(type: string, handle: KeyObjectHandle) {
    if (type !== 'secret' && type !== 'public' && type !== 'private')
      throw new Error(`invalid KeyObject type: ${type}`);
    this.handle = handle;
    this.type = type;
  }

  // get type(): string {
  //   return this.type;
  // }

  // static from(key) {
  //   if (!isCryptoKey(key))
  //     throw new ERR_INVALID_ARG_TYPE('key', 'CryptoKey', key);
  //   return key[kKeyObject];
  // }

  // equals(otherKeyObject) {
  //   if (!isKeyObject(otherKeyObject)) {
  //     throw new ERR_INVALID_ARG_TYPE(
  //       'otherKeyObject',
  //       'KeyObject',
  //       otherKeyObject
  //     );
  //   }

  //   return (
  //     otherKeyObject.type === this.type &&
  //     this[kHandle].equals(otherKeyObject[kHandle])
  //   );
  // }
}

export class SecretKeyObject extends KeyObject {
  constructor(handle: KeyObjectHandle) {
    super('secret', handle);
  }

  // get symmetricKeySize() {
  //   return this[kHandle].getSymmetricKeySize();
  // }

  export(options?: EncodingOptions) {
    if (options !== undefined) {
      if (options.format === 'jwk') {
        throw new Error('SecretKey export for jwk is not implemented');
        // return this.handle.exportJwk({}, false);
      }
    }
    return this.handle.exportKey();
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

  export(options: EncodingOptions) {
    if (options?.format === 'jwk') {
      throw new Error('PublicKey export for jwk is not implemented');
      // return this.handle.exportJwk({}, false);
    }
    const { format, type } = parsePublicKeyEncoding(
      options,
      this.asymmetricKeyType,
    );
    return this.handle.exportKey(format, type);
  }
}

export class PrivateKeyObject extends AsymmetricKeyObject {
  constructor(handle: KeyObjectHandle) {
    super('private', handle);
  }

  export(options: EncodingOptions) {
    if (options?.format === 'jwk') {
      if (options.passphrase !== undefined) {
        throw new Error('jwk does not support encryption');
      }
      throw new Error('PrivateKey export for jwk is not implemented');
      // return this.handle.exportJwk({}, false);
    }
    const { format, type, cipher, passphrase } = parsePrivateKeyEncoding(
      options,
      this.asymmetricKeyType,
    );
    return this.handle.exportKey(format, type, cipher, passphrase);
  }
}
