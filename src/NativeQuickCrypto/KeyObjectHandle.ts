export type KeyObjectHandle = {
  initECRaw(curveName: string, keyData: ArrayBuffer): boolean;
};

export type CreateKeyObjectHandle = () => KeyObjectHandle;
