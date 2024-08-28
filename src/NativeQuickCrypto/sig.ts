// TODO Add real types to sign/verify, the problem is that because of encryption schemes

import type { KeyObjectHandle } from './webcrypto';

// they will have variable amount of parameters
export type InternalSign = {
  init: (algorithm: string) => void;
  update: (data: ArrayBuffer) => void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  sign: (...args: any) => Uint8Array; // returns raw bytes
};

export type InternalVerify = {
  init: (algorithm: string) => void;
  update: (data: ArrayBuffer) => void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
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
  data: ArrayBuffer,
  digest: string | undefined,
  salt_length: number | undefined,
  padding: number | undefined,
  dsa_encoding: DSASigEnc | undefined,
  signature: ArrayBuffer | undefined
) => ArrayBuffer | boolean;
