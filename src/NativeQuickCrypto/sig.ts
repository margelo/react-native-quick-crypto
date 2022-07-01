// TODO Add real types to sign/verify, the problem is that because of encryption schemes
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
