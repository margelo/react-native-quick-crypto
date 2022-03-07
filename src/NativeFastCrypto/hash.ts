type InternalHash = {
  update: (data: ArrayBuffer) => InternalHash;
  digest: () => ArrayBuffer;
};

export type CreateHashMethod = (
  algorithm: string,
  outputLength?: number
) => InternalHash;
