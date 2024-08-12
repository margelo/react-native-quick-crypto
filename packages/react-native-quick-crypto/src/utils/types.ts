export type ArrayBufferView = TypedArray | DataView | ArrayBufferLike | Buffer;

export type TypedArray =
  | Uint8Array
  | Uint8ClampedArray
  | Uint16Array
  | Uint32Array
  | Int8Array
  | Int16Array
  | Int32Array
  | Float32Array
  | Float64Array;

  export type RandomCallback<T> = (err: Error | null, value: T) => void;
  