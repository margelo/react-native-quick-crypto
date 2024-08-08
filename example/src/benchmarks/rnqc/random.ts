import rnqc from 'react-native-quick-crypto';
import { RandomBytesFn } from '../types';

const randomBytes: RandomBytesFn = (len: number) => {
  rnqc.randomBytes(len);
};

export default {
  randomBytes,
};
