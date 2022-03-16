import 'mocha';
import type * as MochaTypes from 'mocha';

export const rootSuite = new Mocha.Suite('') as MochaTypes.Suite;

let mochaContext = rootSuite;

export const it = (
  name: string,
  f: MochaTypes.Func | MochaTypes.AsyncFunc
): void => {
  mochaContext.addTest(new Mocha.Test(name, f) as MochaTypes.Test);
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
