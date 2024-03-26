import { assert } from 'chai';

export const assertThrowsAsync = async (fn: any, expectedMessage: string) => {
  try {
    await fn();
  } catch (err: any) {
    if (expectedMessage) {
      assert.include(
        err.message,
        expectedMessage,
        `Function failed as expected, but could not find message snippet '${expectedMessage}'.  Saw '${err.message}' instead.`
      );
    }
    return;
  }
  assert.fail('function did not throw as expected');
};
