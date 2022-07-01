import type { Buffer } from '@craftzdog/react-native-buffer';

export type InternalSign = {
  init: (algorithm: string) => void;
  update: (data: ArrayBuffer) => void;
  sign: (...args: any) => ArrayBuffer;
};

export type CreateSignMethod = () => InternalSign;
