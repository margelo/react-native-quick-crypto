export type InternalHash = {
  update: (data: ArrayBuffer) => InternalHash;
  digest: () => ArrayBuffer;
  copy: (len?: number) => InternalHash;
};

export type CipherObject = {
  update: (
    data: ArrayBuffer,
    inputEncoding: string,
    outputEncoding: string
  ) => CipherObject;
  final: () => ArrayBuffer;
  copy: (len?: number) => InternalHash;
};
