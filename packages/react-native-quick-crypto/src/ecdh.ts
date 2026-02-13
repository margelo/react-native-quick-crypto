import { NitroModules } from 'react-native-nitro-modules';
import type { ECDH as ECDHInterface } from './specs/ecdh.nitro';
import { Buffer } from '@craftzdog/react-native-buffer';

const POINT_CONVERSION_COMPRESSED = 2;
const POINT_CONVERSION_UNCOMPRESSED = 4;
const POINT_CONVERSION_HYBRID = 6;

export class ECDH {
  private static _convertKeyHybrid: ECDHInterface | undefined;
  private static get convertKeyHybrid(): ECDHInterface {
    if (!this._convertKeyHybrid) {
      this._convertKeyHybrid =
        NitroModules.createHybridObject<ECDHInterface>('ECDH');
    }
    return this._convertKeyHybrid;
  }

  private _hybrid: ECDHInterface;

  constructor(curveName: string) {
    this._hybrid = NitroModules.createHybridObject<ECDHInterface>('ECDH');
    this._hybrid.init(curveName);
  }

  generateKeys(): Buffer {
    const key = this._hybrid.generateKeys();
    return Buffer.from(key);
  }

  computeSecret(
    otherPublicKey: Buffer | string | { code: number; byteLength: number },
    inputEncoding?: BufferEncoding,
  ): Buffer {
    let keyBuf: Buffer;
    if (Buffer.isBuffer(otherPublicKey)) {
      keyBuf = otherPublicKey;
    } else if (typeof otherPublicKey === 'string') {
      keyBuf = Buffer.from(otherPublicKey, inputEncoding);
    } else {
      // Handle array view or other types if necessary, but Node.js typically expects Buffer or string + encoding
      throw new TypeError('Invalid otherPublicKey type');
    }

    // ECDH.computeSecret in Node.js returns Buffer
    const secret = this._hybrid.computeSecret(keyBuf.buffer as ArrayBuffer);
    return Buffer.from(secret);
  }

  getPrivateKey(): Buffer {
    return Buffer.from(this._hybrid.getPrivateKey());
  }

  setPrivateKey(privateKey: Buffer | string, encoding?: BufferEncoding): void {
    let keyBuf: Buffer;
    if (Buffer.isBuffer(privateKey)) {
      keyBuf = privateKey;
    } else {
      keyBuf = Buffer.from(privateKey, encoding);
    }
    this._hybrid.setPrivateKey(keyBuf.buffer as ArrayBuffer);
  }

  getPublicKey(encoding?: BufferEncoding): Buffer | string {
    // Node.js getPublicKey([encoding[, format]])
    // If encoding is provided, returns string. If not, Buffer.
    // Our C++ returns ArrayBuffer (Buffer).
    // We ignore format for now as C++ implementation defaults to uncompressed.
    const pub = Buffer.from(this._hybrid.getPublicKey());
    if (encoding) {
      return pub.toString(encoding);
    }
    return pub;
  }

  setPublicKey(publicKey: Buffer | string, encoding?: BufferEncoding): void {
    let keyBuf: Buffer;
    if (Buffer.isBuffer(publicKey)) {
      keyBuf = publicKey;
    } else {
      keyBuf = Buffer.from(publicKey, encoding);
    }
    this._hybrid.setPublicKey(keyBuf.buffer as ArrayBuffer);
  }

  static convertKey(
    key: Buffer | string,
    curve: string,
    inputEncoding?: BufferEncoding,
    outputEncoding?: BufferEncoding,
    format?: 'uncompressed' | 'compressed' | 'hybrid',
  ): Buffer | string {
    let keyBuf: Buffer;
    if (Buffer.isBuffer(key)) {
      keyBuf = key;
    } else {
      keyBuf = Buffer.from(key, inputEncoding);
    }

    let formatNum: number;
    switch (format) {
      case 'compressed':
        formatNum = POINT_CONVERSION_COMPRESSED;
        break;
      case 'hybrid':
        formatNum = POINT_CONVERSION_HYBRID;
        break;
      case 'uncompressed':
      case undefined:
        formatNum = POINT_CONVERSION_UNCOMPRESSED;
        break;
      default:
        throw new TypeError(
          `Invalid point conversion format: ${format as string}`,
        );
    }

    const result = Buffer.from(
      ECDH.convertKeyHybrid.convertKey(
        keyBuf.buffer as ArrayBuffer,
        curve,
        formatNum,
      ),
    );

    if (outputEncoding) {
      return result.toString(outputEncoding);
    }
    return result;
  }
}

export function createECDH(curveName: string): ECDH {
  return new ECDH(curveName);
}
