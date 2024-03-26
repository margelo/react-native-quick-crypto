import type {
  AsymmetricKeyType,
  KeyEncoding,
  KeyType,
  KFormatType,
  KWebCryptoKeyFormat,
} from '../keys';

type ECExportKey = (
  format: KWebCryptoKeyFormat,
  handle: KeyObjectHandle
) => ArrayBuffer;

export type KeyObjectHandle = {
  export(
    format?: KFormatType,
    type?: KeyEncoding,
    cipher?: string,
    passphrase?: string
  ): ArrayBuffer;
  getAsymmetricKeyType(): AsymmetricKeyType;
  initECRaw(curveName: string, keyData: ArrayBuffer): boolean;
  init(keyType: KeyType, key: any): boolean;
};

type CreateKeyObjectHandle = () => KeyObjectHandle;

export type webcrypto = {
  ecExportKey: ECExportKey;
  createKeyObjectHandle: CreateKeyObjectHandle;
};
