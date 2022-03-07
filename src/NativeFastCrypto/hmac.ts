type InternalHmac = {
  update: (data: ArrayBuffer) => InternalHmac;
  digest: () => ArrayBuffer;
};

export type CreateHmacMethod = (
  algorithm: string,
  key?: string
) => InternalHmac;
