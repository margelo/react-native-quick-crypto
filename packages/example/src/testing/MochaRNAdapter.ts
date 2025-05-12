import 'mocha';
import type * as MochaTypes from 'mocha';

// polyfill encoders for all tests (required for jose)
import { polyfillGlobal } from 'react-native/Libraries/Utilities/PolyfillFunctions';
import RNFE from 'react-native-fast-encoder';
polyfillGlobal('TextEncoder', () => RNFE);
polyfillGlobal('TextDecoder', () => RNFE);

export const rootSuite = new Mocha.Suite('') as MochaTypes.Suite;
rootSuite.timeout(10 * 1000);

let mochaContext = rootSuite;

export const it = (
  name: string,
  f: MochaTypes.Func | MochaTypes.AsyncFunc,
): void => {
  const test = new Mocha.Test(name, f);
  mochaContext.addTest(test);
};

export const describe = (name: string, f: () => void): void => {
  const prevMochaContext = mochaContext;
  mochaContext = new Mocha.Suite(
    name,
    prevMochaContext.ctx,
  ) as MochaTypes.Suite;
  prevMochaContext.addSuite(mochaContext);
  f();
  mochaContext = prevMochaContext;
};
