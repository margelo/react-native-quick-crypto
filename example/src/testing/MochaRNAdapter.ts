import 'mocha';
import type * as MochaTypes from 'mocha';

export const rootSuite = new Mocha.Suite('') as MochaTypes.Suite;
rootSuite.timeout(10 * 1000);

let mochaContext = rootSuite;
let only = false;

export const clearTests = () => {
  rootSuite.suites = [];
  rootSuite.tests = [];
  mochaContext = rootSuite;
  only = false;
};

export const it = (
  name: string,
  f: MochaTypes.Func | MochaTypes.AsyncFunc
): void => {
  if (!only) {
    const test = new Mocha.Test(name, f);
    mochaContext.addTest(test);
  }
};

export const itOnly = (
  name: string,
  f: MochaTypes.Func | MochaTypes.AsyncFunc
): void => {
  clearTests();
  const test = new Mocha.Test(name, f);
  mochaContext.addTest(test);
  only = true;
};

export const describe = (name: string, f: () => void): void => {
  const prevMochaContext = mochaContext;
  mochaContext = new Mocha.Suite(
    name,
    prevMochaContext.ctx
  ) as MochaTypes.Suite;
  prevMochaContext.addSuite(mochaContext);
  f();
  mochaContext = prevMochaContext;
};
