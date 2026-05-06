import { NitroModules } from 'react-native-nitro-modules';
import type { SlhDsaKeyPair } from './specs/slhDsaKeyPair.nitro';
import {
  CryptoKey,
  KeyObject,
  PublicKeyObject,
  PrivateKeyObject as PrivateKeyObjectClass,
} from './keys/classes';
import type {
  CryptoKeyPair,
  KeyUsage,
  SubtleAlgorithm,
  SlhDsaAlgorithm,
} from './utils';
import {
  hasAnyNotIn,
  lazyDOMException,
  getUsagesUnion,
  KFormatType,
  KeyEncoding,
} from './utils';

export type SlhDsaVariant = SlhDsaAlgorithm;

export const SLH_DSA_VARIANTS: readonly SlhDsaVariant[] = [
  'SLH-DSA-SHA2-128s',
  'SLH-DSA-SHA2-128f',
  'SLH-DSA-SHA2-192s',
  'SLH-DSA-SHA2-192f',
  'SLH-DSA-SHA2-256s',
  'SLH-DSA-SHA2-256f',
  'SLH-DSA-SHAKE-128s',
  'SLH-DSA-SHAKE-128f',
  'SLH-DSA-SHAKE-192s',
  'SLH-DSA-SHAKE-192f',
  'SLH-DSA-SHAKE-256s',
  'SLH-DSA-SHAKE-256f',
] as const;

export class SlhDsa {
  variant: SlhDsaVariant;
  native: SlhDsaKeyPair;

  constructor(variant: SlhDsaVariant) {
    this.variant = variant;
    this.native =
      NitroModules.createHybridObject<SlhDsaKeyPair>('SlhDsaKeyPair');
    this.native.setVariant(variant);
  }

  async generateKeyPair(): Promise<void> {
    await this.native.generateKeyPair(
      KFormatType.DER,
      KeyEncoding.SPKI,
      KFormatType.DER,
      KeyEncoding.PKCS8,
    );
  }

  generateKeyPairSync(): void {
    this.native.generateKeyPairSync(
      KFormatType.DER,
      KeyEncoding.SPKI,
      KFormatType.DER,
      KeyEncoding.PKCS8,
    );
  }

  getPublicKey(): ArrayBuffer {
    return this.native.getPublicKey();
  }

  getPrivateKey(): ArrayBuffer {
    return this.native.getPrivateKey();
  }

  async sign(message: ArrayBuffer): Promise<ArrayBuffer> {
    return this.native.sign(message);
  }

  signSync(message: ArrayBuffer): ArrayBuffer {
    return this.native.signSync(message);
  }

  async verify(signature: ArrayBuffer, message: ArrayBuffer): Promise<boolean> {
    return this.native.verify(signature, message);
  }

  verifySync(signature: ArrayBuffer, message: ArrayBuffer): boolean {
    return this.native.verifySync(signature, message);
  }
}

export async function slhdsa_generateKeyPairWebCrypto(
  variant: SlhDsaVariant,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKeyPair> {
  if (hasAnyNotIn(keyUsages, ['sign', 'verify'])) {
    throw lazyDOMException(
      `Unsupported key usage for ${variant}`,
      'SyntaxError',
    );
  }

  const publicUsages = getUsagesUnion(keyUsages, 'verify');
  const privateUsages = getUsagesUnion(keyUsages, 'sign');

  if (privateUsages.length === 0) {
    throw lazyDOMException('Usages cannot be empty', 'SyntaxError');
  }

  const slhdsa = new SlhDsa(variant);
  await slhdsa.generateKeyPair();

  const publicKeyData = slhdsa.getPublicKey();
  const privateKeyData = slhdsa.getPrivateKey();

  const pub = KeyObject.createKeyObject(
    'public',
    publicKeyData,
    KFormatType.DER,
    KeyEncoding.SPKI,
  ) as PublicKeyObject;
  const publicKey = new CryptoKey(
    pub,
    { name: variant } as SubtleAlgorithm,
    publicUsages,
    true,
  );

  const priv = KeyObject.createKeyObject(
    'private',
    privateKeyData,
    KFormatType.DER,
    KeyEncoding.PKCS8,
  ) as PrivateKeyObjectClass;
  const privateKey = new CryptoKey(
    priv,
    { name: variant } as SubtleAlgorithm,
    privateUsages,
    extractable,
  );

  return { publicKey, privateKey };
}
