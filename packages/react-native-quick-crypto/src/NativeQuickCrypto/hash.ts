export type InternalHash = {
  update: (data: ArrayBuffer) => InternalHash;
  digest: () => ArrayBuffer;
  copy: (len?: number) => InternalHash;
};

export type CreateHashMethod = (
  algorithm: string,
  outputLength?: number,
) => InternalHash;
