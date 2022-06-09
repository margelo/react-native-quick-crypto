import type { BinaryLike, CipherEncoding } from 'src/Utils';

export type InternalCipher = {
  update: (
    data: BinaryLike | ArrayBufferView,
    inputEncoding: CipherEncoding
  ) => void;
  final: () => void;
  copy: () => void;
};

export type CreateCipherMethod = (params: {
  cipher_type: string;
  cipher_key: ArrayBuffer;
  auth_tag_len: number;
}) => InternalCipher;
