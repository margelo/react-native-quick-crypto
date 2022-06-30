export type InternalSign = {
  init: (algorithm: string) => void;
  update: (data: ArrayBuffer) => void;
};

export type CreateSignMethod = () => InternalSign;
