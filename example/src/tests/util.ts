import { assert } from 'chai';
import type { TestSuites } from '../types/tests';

export const TestsContext: TestSuites = {};

export const test = (
  suiteName: string,
  testName: string,
  fn: () => void | Promise<void>,
): void => {
  if (!TestsContext[suiteName]) {
    TestsContext[suiteName] = { value: false, tests: {} };
  }
  TestsContext[suiteName].tests[testName] = fn;
};

export const assertThrowsAsync = async (
  fn: () => Promise<unknown>,
  expectedMessage: string,
) => {
  try {
    await fn();
  } catch (error) {
    const err = error as Error;
    if (expectedMessage) {
      assert.include(
        err.message,
        expectedMessage,
        `Function failed as expected, but could not find message snippet '${expectedMessage}'.  Saw '${err.message}' instead.`,
      );
    }
    return;
  }
  assert.fail('function did not throw as expected');
};

export const decodeHex = (str: string): Uint8Array => {
  const uint8array = new Uint8Array(Math.ceil(str.length / 2));
  for (let i = 0; i < str.length; ) {
    uint8array[i / 2] = Number.parseInt(str.slice(i, (i += 2)), 16);
  }
  return uint8array;
};
