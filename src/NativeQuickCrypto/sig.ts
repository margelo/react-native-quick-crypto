// TODO Add real types to sign/verify, the problem is that because of encryption schemes

import type { BufferLike } from '../Utils';
import type { KeyObjectHandle } from './webcrypto';

// they will have variable amount of parameters
export type InternalSign = {
  init: (algorithm: string) => void;
  update: (data: ArrayBuffer) => void;
  sign: (...args: any) => Uint8Array; // returns raw bytes
};

export type InternalVerify = {
  init: (algorithm: string) => void;
  update: (data: ArrayBuffer) => void;
  verify: (...args: any) => boolean;
};

export type CreateSignMethod = () => InternalSign;

export type CreateVerifyMethod = () => InternalVerify;

export enum DSASigEnc {
  kSigEncDER,
  kSigEncP1363,
}

export enum SignMode {
  kSignJobModeSign,
  kSignJobModeVerify,
}

export type SignVerify = (
  mode: SignMode,
  handle: KeyObjectHandle,
  unused1: undefined,
  unused2: undefined,
  unused3: undefined,
  data: BufferLike,
  digest: string | undefined,
  salt_length: number | undefined,
  padding: number | undefined,
  dsa_encoding: DSASigEnc | undefined,
  signature: BufferLike | undefined
) => ArrayBuffer | boolean;
