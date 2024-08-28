import type { AESCipher } from './aes';
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
import type {
  GenerateSecretKeyMethod,
  GenerateSecretKeySyncMethod,
} from './keygen';
import type { KeyVariant } from './Cipher';
import type { RSACipher } from './rsa';

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

type RSAExportKey = (
  format: KWebCryptoKeyFormat,
  handle: KeyObjectHandle,
  variant: KeyVariant
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
  init(
    keyType: KeyType,
    key: string | ArrayBuffer,
    format?: KFormatType,
    type?: KeyEncoding,
    passphrase?: string | ArrayBuffer
  ): boolean;
  initECRaw(curveName: string, keyData: ArrayBuffer): boolean;
  initJwk(keyData: JWK, namedCurve?: NamedCurve): KeyType | undefined;
  keyDetail(): KeyDetail;
};

type CreateKeyObjectHandle = () => KeyObjectHandle;

export type webcrypto = {
  aesCipher: AESCipher;
  createKeyObjectHandle: CreateKeyObjectHandle;
  ecExportKey: ECExportKey;
  generateSecretKey: GenerateSecretKeyMethod;
  generateSecretKeySync: GenerateSecretKeySyncMethod;
  rsaCipher: RSACipher;
  rsaExportKey: RSAExportKey;
  signVerify: SignVerify;
};
