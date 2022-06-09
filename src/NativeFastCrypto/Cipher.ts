import type { BinaryLike, CipherEncoding } from 'src/Utils';

export type InternalCipher = {
  update: (
    data: BinaryLike | ArrayBufferView,
    inputEncoding: CipherEncoding
  ) => ArrayBuffer;
  final: (data: undefined | string) => ArrayBuffer;
  copy: () => void;
};

export type CreateCipherMethod = (params: {
  cipher_type: string;
  cipher_key: ArrayBuffer;
  auth_tag_len: number;
}) => InternalCipher;

export type CreateDecipherMethod = (params: {
  cipher_type: string;
  cipher_key: ArrayBuffer;
  auth_tag_len: number;
}) => InternalCipher;
