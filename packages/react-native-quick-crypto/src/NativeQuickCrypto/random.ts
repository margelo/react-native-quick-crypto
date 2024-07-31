export type RandomObject = {
  randomFill: (
    buffer: ArrayBuffer,
    offset: number,
    size: number
  ) => Promise<ArrayBuffer>;
  randomFillSync: (
    buffer: ArrayBuffer,
    offset: number,
    size: number
  ) => ArrayBuffer;
};
