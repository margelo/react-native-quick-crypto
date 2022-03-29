export type InternalHash = {
  update: (data: ArrayBuffer) => InternalHash;
  digest: () => ArrayBuffer;
  copy: () => InternalHash;
};

export type CreateHashMethod = (
  algorithm: string,
  outputLength?: number
) => InternalHash;
