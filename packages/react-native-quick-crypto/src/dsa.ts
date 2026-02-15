import { NitroModules } from 'react-native-nitro-modules';
import { Buffer } from '@craftzdog/react-native-buffer';
import { KeyObject, PublicKeyObject, PrivateKeyObject } from './keys';
import type { DsaKeyPair } from './specs/dsaKeyPair.nitro';
import type { GenerateKeyPairOptions, KeyPairGenConfig } from './utils/types';
import { KFormatType, KeyEncoding } from './utils';

export class Dsa {
  native: DsaKeyPair;

  constructor(modulusLength: number, divisorLength?: number) {
    this.native = NitroModules.createHybridObject<DsaKeyPair>('DsaKeyPair');
    this.native.setModulusLength(modulusLength);
    if (divisorLength !== undefined && divisorLength >= 0) {
      this.native.setDivisorLength(divisorLength);
    }
  }

  async generateKeyPair(): Promise<void> {
    await this.native.generateKeyPair();
  }

  generateKeyPairSync(): void {
    this.native.generateKeyPairSync();
  }
}

function dsa_prepareKeyGenParams(
  options: GenerateKeyPairOptions | undefined,
): Dsa {
  if (!options) {
    throw new Error('Options are required for DSA key generation');
  }

  const { modulusLength, divisorLength } = options;

  if (!modulusLength || modulusLength < 1024) {
    throw new Error('Invalid or missing modulusLength for DSA key generation');
  }

  return new Dsa(modulusLength, divisorLength);
}

function dsa_formatKeyPairOutput(
  dsa: Dsa,
  encoding: KeyPairGenConfig,
): {
  publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
  privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;
} {
  const {
    publicFormat,
    publicType,
    privateFormat,
    privateType,
    cipher,
    passphrase,
  } = encoding;

  const publicKeyData = dsa.native.getPublicKey();
  const privateKeyData = dsa.native.getPrivateKey();

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
    const keyEncoding =
      publicType === KeyEncoding.SPKI ? KeyEncoding.SPKI : KeyEncoding.SPKI;
    const exported = pub.handle.exportKey(format, keyEncoding);
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
    const keyEncoding =
      privateType === KeyEncoding.PKCS8 ? KeyEncoding.PKCS8 : KeyEncoding.PKCS8;
    const exported = priv.handle.exportKey(
      format,
      keyEncoding,
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

export async function dsa_generateKeyPairNode(
  options: GenerateKeyPairOptions | undefined,
  encoding: KeyPairGenConfig,
): Promise<{
  publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
  privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;
}> {
  const dsa = dsa_prepareKeyGenParams(options);
  await dsa.generateKeyPair();
  return dsa_formatKeyPairOutput(dsa, encoding);
}

export function dsa_generateKeyPairNodeSync(
  options: GenerateKeyPairOptions | undefined,
  encoding: KeyPairGenConfig,
): {
  publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
  privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;
} {
  const dsa = dsa_prepareKeyGenParams(options);
  dsa.generateKeyPairSync();
  return dsa_formatKeyPairOutput(dsa, encoding);
}
