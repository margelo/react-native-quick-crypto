export type InternalCipher = {
  update: () => void;
  final: () => void;
  copy: () => void;
};

export type CreateCipherMethod = (params: {
  cipher_type: string;
  cipher_key: ArrayBuffer;
  auth_tag_len: number;
}) => InternalCipher;
