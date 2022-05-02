export type InternalCipher = {
  update: (
    data: ArrayBuffer,
    inputEncoding: string,
    outputEncoding: string
  ) => InternalCipher;
  final: () => ArrayBuffer;
  copy: (len?: number) => InternalHash;
};

export type createInternalCipher = (
  cipher: string,
  outputLength?: number
) => InternalCipher;
