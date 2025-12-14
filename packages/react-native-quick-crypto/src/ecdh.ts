import { NitroModules } from 'react-native-nitro-modules';
import type { ECDH as ECDHInterface } from './specs/ecdh.nitro';
import { Buffer } from '@craftzdog/react-native-buffer';

export class ECDH {
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
}

export function createECDH(curveName: string): ECDH {
  return new ECDH(curveName);
}
