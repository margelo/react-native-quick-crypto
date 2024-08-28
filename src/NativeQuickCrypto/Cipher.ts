import type { GenerateKeyPairReturn } from '../Cipher';
import type { BinaryLike } from '../Utils';
import type { Buffer } from '@craftzdog/react-native-buffer';
import type {
  EncodingOptions,
  KeyEncoding,
  PrivateKeyObject,
  PublicKeyObject,
  SecretKeyObject,
} from '../keys';

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

export const KeyVariantLookup: Record<string, KeyVariant> = {
  'RSASSA-PKCS1-v1_5': KeyVariant.RSA_SSA_PKCS1_v1_5,
  'RSA-PSS': KeyVariant.RSA_PSS,
  'RSA-OAEP': KeyVariant.RSA_OAEP,
  'ECDSA': KeyVariant.DSA,
  'ECDH': KeyVariant.EC,
  'Ed25519': KeyVariant.NID,
  'Ed448': KeyVariant.NID,
  'X25519': KeyVariant.NID,
  'X448': KeyVariant.NID,
  'DH': KeyVariant.DH,
};

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
  type: KeyEncoding | undefined,
  passphrase: string | ArrayBuffer | undefined,
  buffer: ArrayBuffer,
  padding: number,
  oaepHash: ArrayBuffer | undefined,
  oaepLabel: ArrayBuffer | undefined
) => Buffer;
export type PrivateDecryptMethod = (
  data: ArrayBuffer,
  format: number,
  type: KeyEncoding | undefined,
  passphrase: string | ArrayBuffer | undefined,
  buffer: ArrayBuffer,
  padding: number,
  oaepHash: ArrayBuffer | undefined,
  oaepLabel: ArrayBuffer | undefined
) => Buffer;

export type GenerateKeyPairMethod = (
  keyVariant: KeyVariant,
  ...rest: unknown[]
) => Promise<GenerateKeyPairReturn>;

export type GenerateKeyPairSyncMethod = (
  keyVariant: KeyVariant,
  ...rest: unknown[]
) => GenerateKeyPairReturn;

export type CreatePublicKeyMethod = (
  key: BinaryLike | EncodingOptions
) => PublicKeyObject;

export type CreatePrivateKeyMethod = (
  key: BinaryLike | EncodingOptions
) => PrivateKeyObject;

export type CreateSecretKeyMethod = (
  key: BinaryLike | EncodingOptions,
  encoding?: string
) => SecretKeyObject;
