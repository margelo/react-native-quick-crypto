import { NativeQuickCrypto } from './NativeQuickCrypto/NativeQuickCrypto';
import type { InternalSign, InternalVerify } from './NativeQuickCrypto/sig';
import Stream from 'stream';

// TODO(osp) same as publicCipher on node this are defined on C++ and exposed to node
// Do the same here
enum DSASigEnc {
  kSigEncDER,
  kSigEncP1363,
}

import {
  BinaryLike,
  binaryLikeToArrayBuffer,
  getDefaultEncoding,
} from './Utils';
import { preparePrivateKey, preparePublicOrPrivateKey } from './keys';

const createInternalSign = NativeQuickCrypto.createSign;
const createInternalVerify = NativeQuickCrypto.createVerify;

function getPadding(options: any) {
  return getIntOption('padding', options);
}

function getSaltLength(options: any) {
  return getIntOption('saltLength', options);
}

function getDSASignatureEncoding(options: any) {
  if (typeof options === 'object') {
    const { dsaEncoding = 'der' } = options;
    if (dsaEncoding === 'der') return DSASigEnc.kSigEncDER;
    else if (dsaEncoding === 'ieee-p1363') return DSASigEnc.kSigEncP1363;
    throw new Error(`options.dsaEncoding: ${dsaEncoding} not a valid encoding`);
  }

  return DSASigEnc.kSigEncDER;
}

function getIntOption(name: string, options: any) {
  const value = options[name];
  if (value !== undefined) {
    if (value === value >> 0) {
      return value;
    }
    throw new Error(`options.${name}: ${value} not a valid int value`);
  }
  return undefined;
}

class Verify extends Stream.Writable {
  private internal: InternalVerify;
  constructor(algorithm: string, options: Stream.WritableOptions) {
    super(options);
    this.internal = createInternalVerify();
    this.internal.init(algorithm);
  }

  _write(chunk: BinaryLike, encoding: string, callback: () => void) {
    this.update(chunk, encoding);
    callback();
  }

  update(data: BinaryLike, encoding?: string) {
    encoding = encoding ?? getDefaultEncoding();
    data = binaryLikeToArrayBuffer(data);
    this.internal.update(data);
    return this;
  }

  verify(
    options: {
      key: string | Buffer;
      format?: string;
      type?: string;
      passphrase?: string;
      padding?: number;
      saltLength?: number;
    },
    signature: BinaryLike
  ): boolean {
    if (!options) {
      throw new Error('Crypto sign key required');
    }

    const { data, format, type, passphrase } =
      preparePublicOrPrivateKey(options);

    const rsaPadding = getPadding(options);
    const pssSaltLength = getSaltLength(options);

    // Options specific to (EC)DSA
    const dsaSigEnc = getDSASignatureEncoding(options);

    const ret = this.internal.verify(
      data,
      format,
      type,
      passphrase,
      binaryLikeToArrayBuffer(signature),
      rsaPadding,
      pssSaltLength,
      dsaSigEnc
    );

    return ret;
  }
}

class Sign extends Stream.Writable {
  private internal: InternalSign;
  constructor(algorithm: string, options: Stream.WritableOptions) {
    super(options);
    this.internal = createInternalSign();
    this.internal.init(algorithm);
  }

  _write(chunk: BinaryLike, encoding: string, callback: () => void) {
    this.update(chunk, encoding);
    callback();
  }

  update(data: BinaryLike, encoding?: string) {
    encoding = encoding ?? getDefaultEncoding();
    data = binaryLikeToArrayBuffer(data);
    this.internal.update(data);
    return this;
  }

  sign(
    options: {
      key: string | Buffer;
      format?: string;
      type?: string;
      passphrase?: string;
      padding?: number;
      saltLength?: number;
    },
    encoding?: string
  ) {
    if (!options) {
      throw new Error('Crypto sign key required');
    }

    const { data, format, type, passphrase } = preparePrivateKey(options);

    const rsaPadding = getPadding(options);
    const pssSaltLength = getSaltLength(options);

    // Options specific to (EC)DSA
    const dsaSigEnc = getDSASignatureEncoding(options);

    const ret = this.internal.sign(
      data,
      format,
      type,
      passphrase,
      rsaPadding,
      pssSaltLength,
      dsaSigEnc
    );

    encoding = encoding || getDefaultEncoding();
    if (encoding && encoding !== 'buffer') {
      return Buffer.from(ret).toString(encoding as any);
    }

    return Buffer.from(ret);
  }
}

export function createSign(algorithm: string, options?: any) {
  return new Sign(algorithm, options);
}

export function createVerify(algorithm: string, options?: any) {
  return new Verify(algorithm, options);
}
