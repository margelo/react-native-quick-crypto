// @ts-ignore
import * as them from 'crypto-browserify';
import type { RandomBytesFn } from '../types';

const randomBytes: RandomBytesFn = (len: number) => {
  them.randomBytes(len);
};

export default {
  randomBytes,
};
