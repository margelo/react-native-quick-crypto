import 'mocha';
import type * as MochaTypes from 'mocha';

export const rootSuite = new Mocha.Suite('') as MochaTypes.Suite;

let mochaContext = rootSuite;
let only = false;

export const clearTests = () => {
  rootSuite.suites = [];
  rootSuite.tests = [];
  mochaContext = rootSuite;
  only = false;
};

export const it = (name: string, f: () => void): void => {
  if (!only) {
    mochaContext.addTest(new Mocha.Test(name, f) as MochaTypes.Test);
  }
};

export const itOnly = (name: string, f: () => void): void => {
  clearTests();
  mochaContext.addTest(new Mocha.Test(name, f) as MochaTypes.Test);
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
