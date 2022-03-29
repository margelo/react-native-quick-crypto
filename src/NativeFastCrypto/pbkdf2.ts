export type Pbkdf2Object = {
  pbkdf2: (
    password: ArrayBuffer,
    salt: ArrayBuffer,
    iterations: number,
    keylen: number,
    digest: string
  ) => Promise<ArrayBuffer>;
  pbkdf2Sync: (
    password: ArrayBuffer,
    salt: ArrayBuffer,
    iterations: number,
    keylen: number,
    digest: string
  ) => ArrayBuffer;
};
