import type { Buffer } from '@craftzdog/react-native-buffer';

export type InternalSign = {
  init: (algorithm: string) => void;
  update: (data: ArrayBuffer) => void;
  sign: (...args: any) => Buffer;
};

export type CreateSignMethod = () => InternalSign;
