import type { TestSuites } from '../types/tests';
import { StressContext } from '../stress/util';
import { useSuiteList } from './useSuiteList';

import '../stress/ecdsa_sign_verify';

export const useStressList = (): [
  TestSuites,
  (description: string) => void,
  () => void,
  () => void,
] => useSuiteList(StressContext);
