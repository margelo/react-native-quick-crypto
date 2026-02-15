import { NitroModules } from 'react-native-nitro-modules';
import { Buffer } from '@craftzdog/react-native-buffer';
import { KeyObject, PublicKeyObject, PrivateKeyObject } from './keys';
import type { DhKeyPair } from './specs/dhKeyPair.nitro';
import type { GenerateKeyPairOptions, KeyPairGenConfig } from './utils/types';
import { KFormatType, KeyEncoding } from './utils';
import { DH_GROUPS } from './dh-groups';

export class DhKeyPairGen {
  native: DhKeyPair;

  constructor(options: GenerateKeyPairOptions) {
    this.native = NitroModules.createHybridObject<DhKeyPair>('DhKeyPair');

    const { groupName, prime, primeLength, generator } = options;

    if (groupName) {
      // Resolve named group to prime + generator
      const group = DH_GROUPS[groupName];
      if (!group) {
        throw new Error(`Unknown DH group: ${groupName}`);
      }
      const primeBuf = Buffer.from(group.prime, 'hex');
      this.native.setPrime(
        primeBuf.buffer.slice(
          primeBuf.byteOffset,
          primeBuf.byteOffset + primeBuf.byteLength,
        ) as ArrayBuffer,
      );
      const gen = parseInt(group.generator, 16);
      this.native.setGenerator(gen);
    } else if (prime) {
      // Custom prime as Buffer
      const primeBuf = Buffer.from(prime);
      this.native.setPrime(
        primeBuf.buffer.slice(
          primeBuf.byteOffset,
          primeBuf.byteOffset + primeBuf.byteLength,
        ) as ArrayBuffer,
      );
      this.native.setGenerator(generator ?? 2);
    } else if (primeLength) {
      this.native.setPrimeLength(primeLength);
      this.native.setGenerator(generator ?? 2);
    } else {
      throw new Error(
        'DH key generation requires one of: groupName, prime, or primeLength',
      );
    }
  }

  async generateKeyPair(): Promise<void> {
    await this.native.generateKeyPair();
  }

  generateKeyPairSync(): void {
    this.native.generateKeyPairSync();
  }
}

function dh_prepareKeyGenParams(
  options: GenerateKeyPairOptions | undefined,
): DhKeyPairGen {
  if (!options) {
    throw new Error('Options are required for DH key generation');
  }

  return new DhKeyPairGen(options);
}

function dh_formatKeyPairOutput(
  dh: DhKeyPairGen,
  encoding: KeyPairGenConfig,
): {
  publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
  privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;
} {
  const { publicFormat, privateFormat, cipher, passphrase } = encoding;

  const publicKeyData = dh.native.getPublicKey();
  const privateKeyData = dh.native.getPrivateKey();

  const pub = KeyObject.createKeyObject(
    'public',
    publicKeyData,
    KFormatType.DER,
    KeyEncoding.SPKI,
  ) as PublicKeyObject;

  const priv = KeyObject.createKeyObject(
    'private',
    privateKeyData,
    KFormatType.DER,
    KeyEncoding.PKCS8,
  ) as PrivateKeyObject;

  let publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
  let privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;

  if (publicFormat === -1) {
    publicKey = pub;
  } else {
    const format =
      publicFormat === KFormatType.PEM ? KFormatType.PEM : KFormatType.DER;
    const exported = pub.handle.exportKey(format, KeyEncoding.SPKI);
    if (format === KFormatType.PEM) {
      publicKey = Buffer.from(new Uint8Array(exported)).toString('utf-8');
    } else {
      publicKey = exported;
    }
  }

  if (privateFormat === -1) {
    privateKey = priv;
  } else {
    const format =
      privateFormat === KFormatType.PEM ? KFormatType.PEM : KFormatType.DER;
    const exported = priv.handle.exportKey(
      format,
      KeyEncoding.PKCS8,
      cipher,
      passphrase,
    );
    if (format === KFormatType.PEM) {
      privateKey = Buffer.from(new Uint8Array(exported)).toString('utf-8');
    } else {
      privateKey = exported;
    }
  }

  return { publicKey, privateKey };
}

export async function dh_generateKeyPairNode(
  options: GenerateKeyPairOptions | undefined,
  encoding: KeyPairGenConfig,
): Promise<{
  publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
  privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;
}> {
  const dh = dh_prepareKeyGenParams(options);
  await dh.generateKeyPair();
  return dh_formatKeyPairOutput(dh, encoding);
}

export function dh_generateKeyPairNodeSync(
  options: GenerateKeyPairOptions | undefined,
  encoding: KeyPairGenConfig,
): {
  publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
  privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;
} {
  const dh = dh_prepareKeyGenParams(options);
  dh.generateKeyPairSync();
  return dh_formatKeyPairOutput(dh, encoding);
}
