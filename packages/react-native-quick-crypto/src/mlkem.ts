import { NitroModules } from 'react-native-nitro-modules';
import type { MlKemKeyPair } from './specs/mlKemKeyPair.nitro';
import {
  CryptoKey,
  KeyObject,
  PublicKeyObject,
  PrivateKeyObject,
  isCryptoKey,
} from './keys';
import type {
  CryptoKeyPair,
  KeyUsage,
  SubtleAlgorithm,
  EncapsulateResult,
  BinaryLike,
} from './utils';
import {
  hasAnyNotIn,
  lazyDOMException,
  getUsagesUnion,
  KFormatType,
  KeyEncoding,
  isStringOrBuffer,
  binaryLikeToArrayBuffer as toAB,
} from './utils';

export type MlKemVariant = 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024';

type MlKemKeyType = 'ml-kem-512' | 'ml-kem-768' | 'ml-kem-1024';

type KeyInput = BinaryLike | KeyObject | CryptoKey | KeyInputObject;

export interface KeyInputObject {
  key: BinaryLike | KeyObject | CryptoKey;
  format?: 'pem' | 'der';
  type?: 'pkcs1' | 'pkcs8' | 'spki' | 'sec1';
}

const ML_KEM_VARIANTS: Record<MlKemKeyType, MlKemVariant> = {
  'ml-kem-512': 'ML-KEM-512',
  'ml-kem-768': 'ML-KEM-768',
  'ml-kem-1024': 'ML-KEM-1024',
};

function isMlKemKeyType(type: string): type is MlKemKeyType {
  return type in ML_KEM_VARIANTS;
}

function unpackEncapsulateResult(packed: ArrayBuffer): EncapsulateResult {
  const view = new DataView(packed);
  const ciphertextLen = view.getUint32(0, true);
  const sharedKeyLen = view.getUint32(4, true);
  const headerSize = 8;
  const ciphertext = packed.slice(headerSize, headerSize + ciphertextLen);
  const sharedKey = packed.slice(
    headerSize + ciphertextLen,
    headerSize + ciphertextLen + sharedKeyLen,
  );
  return { ciphertext, sharedKey };
}

export class MlKem {
  variant: MlKemVariant;
  native: MlKemKeyPair;

  constructor(variant: MlKemVariant) {
    this.variant = variant;
    this.native = NitroModules.createHybridObject<MlKemKeyPair>('MlKemKeyPair');
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

  setPublicKey(keyData: ArrayBuffer, format: number, type: number): void {
    this.native.setPublicKey(keyData, format, type);
  }

  setPrivateKey(keyData: ArrayBuffer, format: number, type: number): void {
    this.native.setPrivateKey(keyData, format, type);
  }

  async encapsulate(): Promise<EncapsulateResult> {
    const packed = await this.native.encapsulate();
    return unpackEncapsulateResult(packed);
  }

  encapsulateSync(): EncapsulateResult {
    const packed = this.native.encapsulateSync();
    return unpackEncapsulateResult(packed);
  }

  async decapsulate(ciphertext: ArrayBuffer): Promise<ArrayBuffer> {
    return this.native.decapsulate(ciphertext);
  }

  decapsulateSync(ciphertext: ArrayBuffer): ArrayBuffer {
    return this.native.decapsulateSync(ciphertext);
  }
}

function prepareKey(
  key: KeyInput,
  isPublic: boolean,
): { keyObject: KeyObject } {
  if (key instanceof KeyObject) {
    if (isPublic) {
      if (key.type === 'secret') {
        throw new Error('Cannot use secret key for encapsulation');
      }
    } else {
      if (key.type !== 'private') {
        throw new Error('Key must be a private key for decapsulation');
      }
    }
    return { keyObject: key };
  }

  if (isCryptoKey(key)) {
    const cryptoKey = key as CryptoKey;
    return prepareKey(cryptoKey.keyObject, isPublic);
  }

  if (isStringOrBuffer(key)) {
    const isPem = typeof key === 'string' && key.includes('-----BEGIN');
    const format = isPem ? KFormatType.PEM : undefined;
    const keyType = isPublic ? 'public' : 'private';
    const keyData = toAB(key);
    const keyObject = KeyObject.createKeyObject(keyType, keyData, format);
    return { keyObject };
  }

  if (typeof key === 'object' && 'key' in key) {
    const keyObj = key as KeyInputObject;
    const { key: data, format, type } = keyObj;

    if (data instanceof KeyObject) {
      return { keyObject: data };
    }

    if (isCryptoKey(data)) {
      return { keyObject: (data as CryptoKey).keyObject };
    }

    if (!isStringOrBuffer(data)) {
      throw new Error('Invalid key data type');
    }

    const isPem =
      format === 'pem' ||
      (typeof data === 'string' && data.includes('-----BEGIN'));
    const kFormat = isPem
      ? KFormatType.PEM
      : format === 'der'
        ? KFormatType.DER
        : undefined;

    let kType: KeyEncoding | undefined;
    if (type === 'pkcs8') kType = KeyEncoding.PKCS8;
    else if (type === 'pkcs1') kType = KeyEncoding.PKCS1;
    else if (type === 'sec1') kType = KeyEncoding.SEC1;
    else if (type === 'spki') kType = KeyEncoding.SPKI;

    const keyType = isPublic ? 'public' : 'private';
    const keyData = toAB(data);
    const keyObject = KeyObject.createKeyObject(
      keyType,
      keyData,
      kFormat,
      kType,
    );
    return { keyObject };
  }

  throw new Error('Invalid key input');
}

function getVariantFromKey(keyObject: KeyObject): MlKemVariant {
  const keyType = keyObject.handle.getAsymmetricKeyType();
  if (!isMlKemKeyType(keyType)) {
    throw new Error(
      `Key is not an ML-KEM key. Got asymmetricKeyType: ${keyType}`,
    );
  }
  return ML_KEM_VARIANTS[keyType];
}

export function encapsulate(
  key: KeyInput,
  callback?: (err: Error | null, result?: EncapsulateResult) => void,
): EncapsulateResult | void {
  const doEncapsulate = (): EncapsulateResult => {
    if (key === null || key === undefined) {
      throw new Error('Public key is required for encapsulation');
    }

    const { keyObject } = prepareKey(key, true);
    const variant = getVariantFromKey(keyObject);
    const mlkem = new MlKem(variant);

    const keyData = keyObject.handle.exportKey(
      KFormatType.DER,
      KeyEncoding.SPKI,
    );
    mlkem.setPublicKey(keyData, KFormatType.DER, KeyEncoding.SPKI);

    return mlkem.encapsulateSync();
  };

  if (callback) {
    try {
      const result = doEncapsulate();
      process.nextTick(callback, null, result);
    } catch (err) {
      process.nextTick(callback, err as Error);
    }
    return;
  }

  return doEncapsulate();
}

export function decapsulate(
  key: KeyInput,
  ciphertext: BinaryLike,
  callback?: (err: Error | null, result?: ArrayBuffer) => void,
): ArrayBuffer | void {
  const doDecapsulate = (): ArrayBuffer => {
    if (key === null || key === undefined) {
      throw new Error('Private key is required for decapsulation');
    }

    const { keyObject } = prepareKey(key, false);
    const variant = getVariantFromKey(keyObject);
    const mlkem = new MlKem(variant);

    const keyData = keyObject.handle.exportKey(
      KFormatType.DER,
      KeyEncoding.PKCS8,
    );
    mlkem.setPrivateKey(keyData, KFormatType.DER, KeyEncoding.PKCS8);

    const ciphertextBuffer = toAB(ciphertext) as ArrayBuffer;
    return mlkem.decapsulateSync(ciphertextBuffer);
  };

  if (callback) {
    try {
      const result = doDecapsulate();
      process.nextTick(callback, null, result);
    } catch (err) {
      process.nextTick(callback, err as Error);
    }
    return;
  }

  return doDecapsulate();
}

export async function mlkem_generateKeyPairWebCrypto(
  variant: MlKemVariant,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKeyPair> {
  if (
    hasAnyNotIn(keyUsages, [
      'encapsulateBits',
      'encapsulateKey',
      'decapsulateBits',
      'decapsulateKey',
    ])
  ) {
    throw lazyDOMException(
      `Unsupported key usage for ${variant}`,
      'SyntaxError',
    );
  }

  const publicUsages = getUsagesUnion(
    keyUsages,
    'encapsulateBits',
    'encapsulateKey',
  );
  const privateUsages = getUsagesUnion(
    keyUsages,
    'decapsulateBits',
    'decapsulateKey',
  );

  if (privateUsages.length === 0) {
    throw lazyDOMException('Usages cannot be empty', 'SyntaxError');
  }

  const mlkem = new MlKem(variant);
  await mlkem.generateKeyPair();

  const publicKeyData = mlkem.getPublicKey();
  const privateKeyData = mlkem.getPrivateKey();

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
  ) as PrivateKeyObject;
  const privateKey = new CryptoKey(
    priv,
    { name: variant } as SubtleAlgorithm,
    privateUsages,
    extractable,
  );

  return { publicKey, privateKey };
}
