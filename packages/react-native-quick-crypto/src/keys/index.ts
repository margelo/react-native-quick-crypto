import type { KeyObjectHandle } from '../specs/keyObjectHandle.nitro';
import type { EncodingOptions, KeyUsage, SubtleAlgorithm } from '../utils';

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

class KeyObject {
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
