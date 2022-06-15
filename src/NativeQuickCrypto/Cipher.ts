import type { BinaryLike } from 'src/Utils';

export type InternalCipher = {
  update: (data: BinaryLike | ArrayBufferView) => ArrayBuffer;
  final: () => ArrayBuffer;
  copy: () => void;
  setAAD: (args: {
    data: BinaryLike;
    plaintextLength?: number;
  }) => InternalCipher;
  setAutoPadding: (autoPad: boolean) => boolean;
  setAuthTag: (tag: ArrayBuffer) => boolean;
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

export type PublicEncryptMethod = (
  data: ArrayBuffer,
  format: string,
  type: any,
  passphrase: any,
  buffer: ArrayBuffer,
  padding: number,
  oaepHash: any,
  oaepLabel: any
) => ArrayBuffer;
