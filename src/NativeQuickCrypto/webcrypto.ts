import type { KWebCryptoKeyFormat } from '../keys';

type ECExportKey = (
  format: KWebCryptoKeyFormat,
  handle: KeyObjectHandle
) => ArrayBuffer;

export type KeyObjectHandle = {
  initECRaw(curveName: string, keyData: ArrayBuffer): boolean;
};

type CreateKeyObjectHandle = () => KeyObjectHandle;

export type webcrypto = {
  ecExportKey: ECExportKey;
  createKeyObjectHandle: CreateKeyObjectHandle;
};
