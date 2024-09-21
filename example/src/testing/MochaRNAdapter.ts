import 'mocha';
import type * as MochaTypes from 'mocha';

export const rootSuite = new Mocha.Suite('');
rootSuite.timeout(10 * 1000);

let mochaContext = rootSuite;
const only = false;

export const it = (
  name: string,
  f: MochaTypes.Func | MochaTypes.AsyncFunc,
): void => {
  if (!only) {
    const test = new Mocha.Test(name, f);
    mochaContext.addTest(test);
  }
};

export const describe = (name: string, f: () => void): void => {
  const prevMochaContext = mochaContext;
  mochaContext = new Mocha.Suite(name, prevMochaContext.ctx);
  prevMochaContext.addSuite(mochaContext);
  f();
  mochaContext = prevMochaContext;
};
