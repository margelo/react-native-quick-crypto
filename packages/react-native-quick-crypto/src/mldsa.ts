import { NitroModules } from 'react-native-nitro-modules';
import type { MlDsaKeyPair } from './specs/mlDsaKeyPair.nitro';
import {
  CryptoKey,
  KeyObject,
  PublicKeyObject,
  PrivateKeyObject as PrivateKeyObjectClass,
} from './keys';
import type { CryptoKeyPair, KeyUsage, SubtleAlgorithm } from './utils';
import {
  hasAnyNotIn,
  lazyDOMException,
  getUsagesUnion,
  KFormatType,
  KeyEncoding,
} from './utils';

export type MlDsaVariant = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';

export class MlDsa {
  variant: MlDsaVariant;
  native: MlDsaKeyPair;

  constructor(variant: MlDsaVariant) {
    this.variant = variant;
    this.native = NitroModules.createHybridObject<MlDsaKeyPair>('MlDsaKeyPair');
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

export async function mldsa_generateKeyPairWebCrypto(
  variant: MlDsaVariant,
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

  const mldsa = new MlDsa(variant);
  await mldsa.generateKeyPair();

  const publicKeyData = mldsa.getPublicKey();
  const privateKeyData = mldsa.getPrivateKey();

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
