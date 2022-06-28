import type { BinaryLike } from 'src/Utils';
import type { Buffer } from '@craftzdog/react-native-buffer';

// TODO(osp) on node this is defined on the native side
// Need to do the same so that values are always in sync
export enum RSAKeyVariant {
  kKeyVariantRSA_SSA_PKCS1_v1_5,
  kKeyVariantRSA_PSS,
  kKeyVariantRSA_OAEP,
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
  keyVariant: RSAKeyVariant,
  modulusLength: number,
  publicExponent: number,
  ...rest: any[]
) => Promise<[error: unknown, publicBuffer: any, privateBuffer: any]>;

export type GenerateKeyPairSyncMethod = (
  keyVariant: RSAKeyVariant,
  modulusLength: number,
  publicExponent: number,
  ...rest: any[]
) => [error: unknown, publicBuffer: any, privateBuffer: any];
