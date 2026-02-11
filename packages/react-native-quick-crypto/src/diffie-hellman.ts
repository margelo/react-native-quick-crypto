import { NitroModules } from 'react-native-nitro-modules';
import type { DiffieHellman as DiffieHellmanInterface } from './specs/diffie-hellman.nitro';
import { Buffer } from '@craftzdog/react-native-buffer';
import { DH_GROUPS } from './dh-groups';

export class DiffieHellman {
  private _hybrid: DiffieHellmanInterface;

  constructor(
    sizeOrPrime: number | Buffer | string,
    generator?: number | Buffer | string,
    encoding?: BufferEncoding,
  ) {
    this._hybrid =
      NitroModules.createHybridObject<DiffieHellmanInterface>('DiffieHellman');

    if (typeof sizeOrPrime === 'number') {
      const gen = typeof generator === 'number' ? generator : 2;
      this._hybrid.initWithSize(sizeOrPrime, gen);
    } else {
      let primeBuf: Buffer;
      if (Buffer.isBuffer(sizeOrPrime)) {
        primeBuf = sizeOrPrime;
      } else {
        primeBuf = Buffer.from(sizeOrPrime, encoding as BufferEncoding);
      }

      let genBuf: Buffer;
      if (generator === undefined) {
        genBuf = Buffer.from([2]);
      } else if (typeof generator === 'number') {
        genBuf = Buffer.from([generator]);
      } else if (Buffer.isBuffer(generator)) {
        genBuf = generator;
      } else {
        genBuf = Buffer.from(generator, encoding as BufferEncoding);
      }

      this._hybrid.init(
        primeBuf.buffer as ArrayBuffer,
        genBuf.buffer as ArrayBuffer,
      );
    }
  }

  generateKeys(encoding?: BufferEncoding): Buffer | string {
    const keys = Buffer.from(this._hybrid.generateKeys());
    if (encoding) return keys.toString(encoding);
    return keys;
  }

  computeSecret(
    otherPublicKey: Buffer | string,
    inputEncoding?: BufferEncoding,
    outputEncoding?: BufferEncoding,
  ): Buffer | string {
    let keyBuf: Buffer;
    if (Buffer.isBuffer(otherPublicKey)) {
      keyBuf = otherPublicKey;
    } else {
      keyBuf = Buffer.from(otherPublicKey, inputEncoding);
    }

    const secret = Buffer.from(
      this._hybrid.computeSecret(keyBuf.buffer as ArrayBuffer),
    );
    if (outputEncoding) return secret.toString(outputEncoding);
    return secret;
  }

  getPrime(encoding?: BufferEncoding): Buffer | string {
    const p = Buffer.from(this._hybrid.getPrime());
    if (encoding) return p.toString(encoding);
    return p;
  }

  getGenerator(encoding?: BufferEncoding): Buffer | string {
    const g = Buffer.from(this._hybrid.getGenerator());
    if (encoding) return g.toString(encoding);
    return g;
  }

  getPublicKey(encoding?: BufferEncoding): Buffer | string {
    const p = Buffer.from(this._hybrid.getPublicKey());
    if (encoding) return p.toString(encoding);
    return p;
  }

  getPrivateKey(encoding?: BufferEncoding): Buffer | string {
    const p = Buffer.from(this._hybrid.getPrivateKey());
    if (encoding) return p.toString(encoding);
    return p;
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

  setPrivateKey(privateKey: Buffer | string, encoding?: BufferEncoding): void {
    let keyBuf: Buffer;
    if (Buffer.isBuffer(privateKey)) {
      keyBuf = privateKey;
    } else {
      keyBuf = Buffer.from(privateKey, encoding);
    }
    this._hybrid.setPrivateKey(keyBuf.buffer as ArrayBuffer);
  }

  get verifyError(): number {
    return this._hybrid.getVerifyError();
  }
}

export function createDiffieHellman(
  primeOrSize: number | string | Buffer,
  primeEncodingOrGenerator?: string | number | Buffer,
  generator?: number | string | Buffer,
  _generatorEncoding?: string,
): DiffieHellman {
  if (typeof primeOrSize === 'number') {
    const gen =
      typeof primeEncodingOrGenerator === 'number'
        ? primeEncodingOrGenerator
        : 2;
    return new DiffieHellman(primeOrSize, gen);
  }

  // Standardize arguments for String/Buffer prime
  // createDiffieHellman(prime, [encoding], [generator], [encoding])

  let prime: Buffer;
  let generatorVal: Buffer | number | undefined;

  if (Buffer.isBuffer(primeOrSize)) {
    prime = primeOrSize;
    // 2nd arg is generator if not string (encoding)
    if (
      primeEncodingOrGenerator !== undefined &&
      typeof primeEncodingOrGenerator !== 'string'
    ) {
      generatorVal = primeEncodingOrGenerator as Buffer | number;
    } else if (generator !== undefined) {
      generatorVal = generator as Buffer | number;
    } else {
      generatorVal = 2;
    }
  } else {
    // String prime
    const encoding =
      typeof primeEncodingOrGenerator === 'string'
        ? primeEncodingOrGenerator
        : 'utf8'; // Defaulting to utf8 or hex? Node default is 'binary' usually but utf8 safer for TS. Node docs say: "If no encoding is specified, 'binary' is used."
    // We'll trust user passed encoding if it's a string, otherwise handle it.
    prime = Buffer.from(primeOrSize, encoding as BufferEncoding);

    // Generator handling in this case
    if (generator !== undefined) {
      generatorVal = generator as Buffer | number;
      if (typeof generator === 'string' && _generatorEncoding) {
        generatorVal = Buffer.from(
          generator,
          _generatorEncoding as BufferEncoding,
        );
      } else if (typeof generator === 'string') {
        // string with no encoding, assume same as prime? or utf8?
        generatorVal = Buffer.from(generator, encoding as BufferEncoding);
      }
    } else if (
      typeof primeEncodingOrGenerator !== 'string' &&
      primeEncodingOrGenerator !== undefined
    ) {
      // 2nd arg was generator
      generatorVal = primeEncodingOrGenerator as number;
    } else {
      generatorVal = 2;
    }
  }

  return new DiffieHellman(prime, generatorVal);
}

export function getDiffieHellman(groupName: string): DiffieHellman {
  const group = DH_GROUPS[groupName];
  if (!group) {
    throw new Error(`Unknown group: ${groupName}`);
  }
  // group.prime and group.generator are hex strings
  return new DiffieHellman(group.prime, group.generator, 'hex');
}

export { getDiffieHellman as createDiffieHellmanGroup };
