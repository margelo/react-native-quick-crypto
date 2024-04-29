import type {
  AsymmetricKeyType,
  JWK,
  KeyEncoding,
  KeyType,
  KFormatType,
  KWebCryptoKeyFormat,
  NamedCurve,
} from '../keys';
import type { SignVerify } from './sig';

type KeyDetail = {
  length?: number;
  publicExponent?: number;
  modulusLength?: number;
  hashAlgorithm?: string;
  mgf1HashAlgorithm?: string;
  saltLength?: number;
  namedCurve?: string;
};

type ECExportKey = (
  format: KWebCryptoKeyFormat,
  handle: KeyObjectHandle
) => ArrayBuffer;

export type KeyObjectHandle = {
  export(
    format?: KFormatType,
    type?: KeyEncoding,
    cipher?: string,
    passphrase?: ArrayBuffer
  ): ArrayBuffer;
  exportJwk(key: JWK, handleRsaPss: boolean): JWK;
  getAsymmetricKeyType(): AsymmetricKeyType;
  init(keyType: KeyType, key: any): boolean;
  initECRaw(curveName: string, keyData: ArrayBuffer): boolean;
  initJwk(keyData: JWK, namedCurve?: NamedCurve): KeyType | undefined;
  keyDetail(): KeyDetail;
};

type CreateKeyObjectHandle = () => KeyObjectHandle;

export type webcrypto = {
  ecExportKey: ECExportKey;
  createKeyObjectHandle: CreateKeyObjectHandle;
  signVerify: SignVerify;
};
