export type InternalCipher = {
  update: () => void;
  final: () => void;
  copy: () => void;
};

export type CreateCipherMethod = (
  cipher_type: string,
  password: ArrayBuffer,
  options: any
) => InternalCipher;
