import { assert } from 'chai'

type Fn = () => Promise<void>

export const assertThrowsAsync = async (asyncFn: Fn, expectedMessage: string) => {
  try {
    await asyncFn()
  } catch (err: unknown) {
    if (expectedMessage && err instanceof Error) {
      assert.include(
        err.message,
        expectedMessage,
        `Function failed as expected, but could not find message snippet '${expectedMessage}'.  Saw '${err.message}' instead.`
      )
    }
    return
  }
  assert.fail('function did not throw as expected')
}

export const decodeHex = (str: string): Uint8Array => {
  const uint8array = new Uint8Array(Math.ceil(str.length / 2))
  for (let i = 0; i < str.length; ) {
    uint8array[i / 2] = Number.parseInt(str.slice(i, (i += 2)), 16)
  }
  return uint8array
}
