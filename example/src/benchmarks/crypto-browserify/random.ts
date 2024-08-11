// @ts-ignore
import {randomBytes} from 'crypto-browserify';
import type {RandomBytesFn} from '../types';

const randomBytes10: RandomBytesFn = () => {
  randomBytes(10);
};

const randomBytes1024: RandomBytesFn = () => {
  randomBytes(1024);
};

export default {
  randomBytes10,
  randomBytes1024,
};
