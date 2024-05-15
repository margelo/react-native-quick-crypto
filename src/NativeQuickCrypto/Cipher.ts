import type { GenerateKeyPairReturn } from '../Cipher';
import type { BinaryLike } from '../Utils';
import type { Buffer } from '@craftzdog/react-native-buffer';

// TODO: until shared, keep in sync with C++ side (cpp/Utils/MGLUtils.h)
export enum KeyVariant {
  RSA_SSA_PKCS1_v1_5,
  RSA_PSS,
  RSA_OAEP,
  DSA,
  EC,
  NID,
  DH,
}

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
  getAuthTag: () => ArrayBuffer;
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
  format: number,
  type: any,
  passphrase: any,
  buffer: ArrayBuffer,
  padding: number,
  oaepHash: any,
  oaepLabel: any
) => Buffer;
export type PrivateDecryptMethod = (
  data: ArrayBuffer,
  format: number,
  type: any,
  passphrase: any,
  buffer: ArrayBuffer,
  padding: number,
  oaepHash: any,
  oaepLabel: any
) => Buffer;

export type GenerateKeyPairMethod = (
  keyVariant: KeyVariant,
  ...rest: any[]
) => Promise<GenerateKeyPairReturn>;

export type GenerateKeyPairSyncMethod = (
  keyVariant: KeyVariant,
  ...rest: any[]
) => GenerateKeyPairReturn;
