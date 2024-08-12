// copied from https://github.com/nodejs/node/blob/master/test/parallel/test-crypto-random.js

// Flags: --pending-deprecation
import crypto from 'react-native-quick-crypto'
import { describe, it } from '../../MochaRNAdapter'
import { Buffer } from '@craftzdog/react-native-buffer'
import { assert } from 'chai'
import type { Done } from 'mocha'

const { ab2str, abvToArrayBuffer } = crypto.utils;

describe('random', () => {
  ;[crypto.randomBytes, crypto.pseudoRandomBytes].forEach((f) => {
    // TODO (Szymon)
    // [undefined, null, false, true, {}, []].forEach((value) => {
    //   const errObj = {
    //     code: 'ERR_INVALID_ARG_TYPE',
    //     name: 'TypeError',
    //     message:
    //       'The "size" argument must be of type number.' +
    //       common.invalidArgTypeHelper(value),
    //   };
    //   assert.throws(() => f(value), errObj);
    //   assert.throws(() => f(value, common.mustNotCall()), errObj);
    // });

    // [-1, NaN, 2 ** 32, 2 ** 31].forEach((value) => {
    //   const errObj = {
    //     code: 'ERR_OUT_OF_RANGE',
    //     name: 'RangeError',
    //     message:
    //       'The value of "size" is out of range. It must be >= 0 && <= ' +
    //       `${kMaxPossibleLength}. Received ${value}`,
    //   };
    //   assert.throws(() => f(value), errObj);
    //   assert.throws(() => f(value, common.mustNotCall()), errObj);
    // });

    ;[0, 1, 2, 4, 16, 256, 1024, 101.2].forEach((len) => {
      const length = len
      const funn = f
      it('function ' + funn + ' & len ' + length, (done: Done) => {
        funn(length, (ex: Error | null, buf?: Buffer) => {
          try {
            assert.strictEqual(ex, null)
            assert.strictEqual(buf?.length, Math.floor(len))
            assert.ok(Buffer.isBuffer(buf))
          } catch (e) {
            done(e)
          }
          done()
        })
      })
    })
  })

  it('simple test 1', () => {
    const buf = Buffer.alloc(10)
    const before = buf.toString('hex')
    const after = crypto.randomFillSync(buf).toString('hex')
    assert.notStrictEqual(before, after)
  })

  it('simple test 2', () => {
    const buf = new Uint8Array(new Array(10).fill(0))
    const before = Buffer.from(buf).toString('hex')
    crypto.randomFillSync(buf)
    const after = Buffer.from(buf).toString('hex')
    assert.notStrictEqual(before, after)
  })

  it('simple test 3', () => {
    ;[
      new Uint16Array(10),
      new Uint32Array(10),
      new Float32Array(10),
      new Float64Array(10),
      new DataView(new ArrayBuffer(10)),
    ].forEach((buf) => {
      const before = Buffer.from(buf.buffer).toString('hex')
      crypto.randomFillSync(buf)
      const after = Buffer.from(buf.buffer).toString('hex')
      assert.notStrictEqual(before, after)
    })
  })

  it('simple test 4 - randomFillSync ArrayBuffer', () => {
    ;[new ArrayBuffer(10), new ArrayBuffer(10)].forEach((buf) => {
      const before = Buffer.from(buf).toString('hex')
      crypto.randomFillSync(buf)
      const after = Buffer.from(buf).toString('hex')
      assert.notStrictEqual(before, after)
    })
  })

  it('simple test 5 - randomFill Buffer ', (done: Done) => {
    const buf = Buffer.alloc(10)
    const before = buf.toString('hex')

    crypto.randomFill(buf, (_err: Error | null, res: Buffer) => {
      try {
        const after = res?.toString('hex')
        assert.notStrictEqual(before, after)
        done()
      } catch (e) {
        done(e)
      }
    })
  })

  it('simple test 6', (done: Done) => {
    const buf = new Uint8Array(new Array(10).fill(0))
    const before = Buffer.from(buf).toString('hex')

    crypto.randomFill(buf, (_err: Error | null, res: Uint8Array) => {
      try {
        const after = Buffer.from(res).toString('hex')
        assert.notStrictEqual(before, after)
        done()
      } catch (e) {
        done(e)
      }
    })
  })

  type BufTypes = Uint16Array | Uint32Array | Float32Array | Float64Array | DataView;
  const bufs: [BufTypes, string][] = [
    [new Uint16Array(10), 'Uint16Array'],
    [new Uint32Array(10), 'Uint32Array'],
    [new Float32Array(10), 'Float32Array'],
    [new Float64Array(10), 'Float64Array'],
    [new DataView(new ArrayBuffer(10)), 'DataView'],
  ]
  bufs.forEach(([buf, name]) => {
    it(`simple test 7, ${name}`, (done: Done) => {
      const ab = abvToArrayBuffer(buf)
      const before = ab2str(ab)

      crypto.randomFill(ab, (_err: Error | null, buf2: ArrayBuffer) => {
        try {
          const after = Buffer.from(buf2).toString('hex')
          assert.notStrictEqual(before, after, 'before/after')
          done()
        } catch (e) {
          done(e)
        }
      })
    })
  })

  it('simple test 8', (done: Done) => {
    let ctr = 0
    ;[new ArrayBuffer(10), new ArrayBuffer(10)].forEach((buf) => {
      const before = Buffer.from(buf).toString('hex')
      crypto.randomFill(buf, (_err: Error | null, res: ArrayBuffer) => {
        try {
          const after = Buffer.from(res).toString('hex')
          assert.notStrictEqual(before, after)
        } catch (e) {
          done(e)
        }
        ctr++
        if (ctr === 2) {
          done()
        }
      })
    })
  })

  it('randomFillSync - deepStringEqual - Buffer', () => {
    const buf = Buffer.alloc(10)
    const before = buf.toString('hex')
    crypto.randomFillSync(buf, 5, 5)
    const after = buf.toString('hex')
    assert.notStrictEqual(before, after, 'before/after')
    assert.deepStrictEqual(
      before.slice(0, 5),
      after.slice(0, 5),
      'before/after slices'
    )
  })

  it('randomFillSync - deepStringEqual - Uint8Array', () => {
    const buf = new Uint8Array(new Array(10).fill(0))
    const before = Buffer.from(buf).toString('hex')
    crypto.randomFillSync(buf, 5, 5)
    const after = Buffer.from(buf).toString('hex')
    assert.notStrictEqual(before, after, 'before/after')
    assert.deepStrictEqual(
      before.slice(0, 5),
      after.slice(0, 5),
      'before/after slices'
    )
  })

  it('randomFillSync - deepStringEqual - Buffer no size', () => {
    const buf = Buffer.alloc(10)
    const before = buf.toString('hex')
    crypto.randomFillSync(buf, 5)
    const after = buf.toString('hex')
    assert.notStrictEqual(before, after, 'before/after')
    assert.deepStrictEqual(
      before.slice(0, 5),
      after.slice(0, 5),
      'before/after slices'
    )
  })

  it('randomFill - deepStringEqual - Buffer', (done: Done) => {
    const buf = Buffer.alloc(10)
    const before = buf.toString('hex')

    crypto.randomFill(buf, 5, 5, (_err: Error | null, res: Buffer) => {
      try {
        const after = Buffer.from(res).toString('hex')
        assert.notStrictEqual(before, after, 'before/after')
        assert.deepStrictEqual(
          before.slice(0, 5),
          after.slice(0, 5),
          'before/after slices'
        )
        done()
      } catch (e) {
        done(e)
      }
    })
  })

  it('randomFill - deepStringEqual - Uint8Array', (done: Done) => {
    const buf = new Uint8Array(new Array(10).fill(0))
    const before = Buffer.from(buf).toString('hex')
    crypto.randomFill(buf, 5, 5, (_err: Error | null, res: Uint8Array) => {
      try {
        const after = Buffer.from(res).toString('hex')
        assert.notStrictEqual(before, after, 'before/after')
        assert.deepStrictEqual(
          before.slice(0, 5),
          after.slice(0, 5),
          'before/after slices'
        )
        done()
      } catch (e) {
        done(e)
      }
    })
  })

  //   finish
  // describe('errors checks', () => {
  //   [Buffer.alloc(10), new Uint8Array(new Array(10).fill(0))].forEach((buf) => {
  //     const buffer = buf;
  //     it('Expected byteLength of 10', () => {
  //       const len = Buffer.byteLength(buffer);
  //       assert.strictEqual(len, 10, `Expected byteLength of 10, got ${len}`);
  //     });

  //     const typeErrObj = {
  //       code: 'ERR_INVALID_ARG_TYPE',
  //       name: 'TypeError',
  //       message:
  //         'The "offset" argument must be of type number. ' +
  //         "Received type string ('test')",
  //     };

  //     it('offset must be a number', () => {
  //       assert.throws(
  //         () => crypto.randomFillSync(buffer, 'test'),
  //         /ERR_INVALID_ARG_TYPE/,
  //         typeErrObj.message
  //       );
  //     });

  //     it('offsetMustBe a number ', () => {
  //       assert.throws(
  //         () => crypto.randomFill(buffer, 'test', () => {}),
  //         typeErrObj
  //       );
  //     });

  //     typeErrObj.message = typeErrObj.message.replace('offset', 'size');
  //     assert.throws(() => crypto.randomFillSync(buffer, 0, 'test'), typeErrObj);

  //     assert.throws(
  //       () => crypto.randomFill(buffer, 0, 'test', () => {})),
  //       typeErrObj
  //     );

  //     [NaN, kMaxPossibleLength + 1, -10, (-1 >>> 0) + 1].forEach(
  //       (offsetSize) => {
  //         const errObj = {
  //           code: 'ERR_OUT_OF_RANGE',
  //           name: 'RangeError',
  //           message:
  //             'The value of "offset" is out of range. ' +
  //             `It must be >= 0 && <= 10. Received ${offsetSize}`,
  //         };

  //         assert.throws(() => crypto.randomFillSync(buf, offsetSize), errObj);

  //         assert.throws(
  //           () => crypto.randomFill(buffer, offsetSize, () => {}),
  //           errObj
  //         );

  //         errObj.message =
  //           'The value of "size" is out of range. It must be >= ' +
  //           `0 && <= ${kMaxPossibleLength}. Received ${offsetSize}`;
  //         assert.throws(
  //           () => crypto.randomFillSync(buffer, 1, offsetSize),
  //           errObj
  //         );

  //         assert.throws(
  //           () => crypto.randomFill(buffer, 1, offsetSize, () => {}),
  //           errObj
  //         );
  //       }
  //     );

  //     const rangeErrObj = {
  //       code: 'ERR_OUT_OF_RANGE',
  //       name: 'RangeError',
  //       message:
  //         'The value of "size + offset" is out of range. ' +
  //         'It must be <= 10. Received 11',
  //     };
  //     assert.throws(() => crypto.randomFillSync(buf, 1, 10), rangeErrObj);

  //     assert.throws(() => crypto.randomFill(buf, 1, 10, () => {}), rangeErrObj);
  //   });
  // });

  // https://github.com/nodejs/node-v0.x-archive/issues/5126,
  // "FATAL ERROR: v8::Object::SetIndexedPropertiesToExternalArrayData() length
  // exceeds max acceptable value"
  //   handle errors properly

  // assert.throws(() => crypto.randomBytes((-1 >>> 0) + 1), {
  //   code: 'ERR_OUT_OF_RANGE',
  //   name: 'RangeError',
  //   message:
  //     'The value of "size" is out of range. ' +
  //     `It must be >= 0 && <= ${kMaxPossibleLength}. Received 4294967296`,
  // });

  // [1, true, NaN, null, undefined, {}, []].forEach((i) => {
  //   const buf = Buffer.alloc(10);
  //   assert.throws(() => crypto.randomFillSync(i), {
  //     code: 'ERR_INVALID_ARG_TYPE',
  //     name: 'TypeError',
  //   });
  //   assert.throws(() => crypto.randomFill(i, common.mustNotCall()), {
  //     code: 'ERR_INVALID_ARG_TYPE',
  //     name: 'TypeError',
  //   });
  //   assert.throws(() => crypto.randomFill(buf, 0, 10, i), {
  //     code: 'ERR_INVALID_ARG_TYPE',
  //     name: 'TypeError',
  //   });
  // });

  // [1, true, NaN, null, {}, []].forEach((i) => {
  //   assert.throws(() => crypto.randomBytes(1, i), {
  //     code: 'ERR_INVALID_ARG_TYPE',
  //     name: 'TypeError',
  //   });
  // });
  ;['pseudoRandomBytes', 'prng', 'rng'].forEach((name) => {
    it(name, () => {
      const desc = Object.getOwnPropertyDescriptor(crypto, name)
      assert.ok(desc, 'descriptor')
      assert.strictEqual(desc?.configurable, true, `${name} configurable`)
      // TODO: re-enable this?
      // assert.strictEqual(desc?.enumerable, false, `${name} enumerable`);
    })
  })

  it('randomInt - Asynchronous API', (done: Done) => {
    const randomInts: number[] = []
    let failed = false
    for (let i = 0; i < 100; i++) {
      crypto.randomInt(3, (_err: Error | null, n: number) => {
        try {
          assert.ok(n >= 0, `${n} >= 0`)
          assert.ok(n < 3, `${n} < 3`)
          randomInts.push(n)
          if (randomInts.length === 100) {
            assert.ok(!randomInts.includes(-1), '!includes(-1)')
            assert.ok(randomInts.includes(0), 'includes(0)')
            assert.ok(randomInts.includes(1), 'includes(1)')
            assert.ok(randomInts.includes(2), 'includes(2)')
            assert.ok(!randomInts.includes(3), 'includes(3)')
            done()
          }
        } catch (e) {
          if (!failed) {
            done(e)
            failed = true
          }
        }
      })
    }
  })

  it('randomInt - Synchronous API', () => {
    const randomInts = []
    for (let i = 0; i < 100; i++) {
      const n = crypto.randomInt(3)
      assert.ok(n >= 0)
      assert.ok(n < 3)
      randomInts.push(n)
    }

    assert.ok(!randomInts.includes(-1), '!includes(-1)')
    assert.ok(randomInts.includes(0), 'includes(0)')
    assert.ok(randomInts.includes(1), 'includes(1)')
    assert.ok(randomInts.includes(2), 'includes(2)')
    assert.ok(!randomInts.includes(3), 'includes(3)')
  })

  it('randomInt positive range', (done: Done) => {
    const randomInts: number[] = []
    let failed = false
    for (let i = 0; i < 100; i++) {
      crypto.randomInt(1, 3, (_err: Error | null, n: number) => {
        try {
          assert.ok(n >= 1)
          assert.ok(n < 3)
          randomInts.push(n)
          if (randomInts.length === 100) {
            assert.ok(randomInts.includes(1))
            assert.ok(randomInts.includes(2))
            done()
          }
        } catch (e) {
          if (!failed) {
            done(e)
            failed = true
          }
        }
      })
    }
  })

  it('randomInt negative range', (done: Done) => {
    const randomInts: number[] = []
    let failed = false
    for (let i = 0; i < 100; i++) {
      crypto.randomInt(-10, -8, (_err: Error | null, n: number) => {
        try {
          assert.ok(n >= -10)
          assert.ok(n < -8)
          randomInts.push(n)
          if (randomInts.length === 100) {
            assert.ok(!randomInts.includes(-11))
            assert.ok(randomInts.includes(-10))
            assert.ok(randomInts.includes(-9))
            assert.ok(!randomInts.includes(-8))
            done()
          }
        } catch (e) {
          if (!failed) {
            done(e)
            failed = true
          }
        }
      })
    }
  })

  // ['10', true, NaN, null, {}, []].forEach((i) => {
  //   const invalidMinError = {
  //     code: 'ERR_INVALID_ARG_TYPE',
  //     name: 'TypeError',
  //     message:
  //       'The "min" argument must be a safe integer.' +
  //       `${common.invalidArgTypeHelper(i)}`,
  //   };
  //   const invalidMaxError = {
  //     code: 'ERR_INVALID_ARG_TYPE',
  //     name: 'TypeError',
  //     message:
  //       'The "max" argument must be a safe integer.' +
  //       `${common.invalidArgTypeHelper(i)}`,
  //   };

  //   assert.throws(() => crypto.randomInt(i, 100), invalidMinError);
  //   assert.throws(
  //     () => crypto.randomInt(i, 100, common.mustNotCall()),
  //     invalidMinError
  //   );
  //   assert.throws(() => crypto.randomInt(i), invalidMaxError);
  //   assert.throws(
  //     () => crypto.randomInt(i, common.mustNotCall()),
  //     invalidMaxError
  //   );
  //   assert.throws(
  //     () => crypto.randomInt(0, i, common.mustNotCall()),
  //     invalidMaxError
  //   );
  //   assert.throws(() => crypto.randomInt(0, i), invalidMaxError);
  // });

  // assert.throws(
  //   () => crypto.randomInt(minInt - 1, minInt + 5, common.mustNotCall()),
  //   {
  //     code: 'ERR_INVALID_ARG_TYPE',
  //     name: 'TypeError',
  //     message:
  //       'The "min" argument must be a safe integer.' +
  //       `${common.invalidArgTypeHelper(minInt - 1)}`,
  //   }
  // );

  // assert.throws(() => crypto.randomInt(maxInt + 1, common.mustNotCall()), {
  //   code: 'ERR_INVALID_ARG_TYPE',
  //   name: 'TypeError',
  //   message:
  //     'The "max" argument must be a safe integer.' +
  //     `${common.invalidArgTypeHelper(maxInt + 1)}`,
  // });

  for (const arg of [[0], [1, 1], [3, 2], [-5, -5], [11, -10]]) {
    const interval = arg
    it('range' + interval.toString(), () => {
      assert.throws(
        () => crypto.randomInt(1, MAX_RANGE + 2, () => {}),
        /ERR_OUT_OF_RANGE/,
        'The value of "max" is out of range. It must be greater than ' +
          `the value of "min" (${interval[interval.length - 2] || 0}). ` +
          `Received ${interval[interval.length - 1]}`
      )
    })
  }

  const MAX_RANGE = 0xffffffffffff
  const maxInt = Number.MAX_SAFE_INTEGER
  const minInt = Number.MIN_SAFE_INTEGER

  it('minInt, minInt + 5 ', (done: Done) => {
    crypto.randomInt(minInt, minInt + 5, () => {
      done()
    })
  })

  it('maxint - 5, maxint', (done: Done) => {
    crypto.randomInt(maxInt - 5, maxInt, () => {
      done()
    })
  })

  it('1', (done: Done) => {
    crypto.randomInt(1, () => {
      done()
    })
  })

  it('0 - 1', (done: Done) => {
    crypto.randomInt(0, 1, () => {
      done()
    })
  })

  it('maxRange', (done: Done) => {
    crypto.randomInt(MAX_RANGE, () => {
      done()
    })
  })

  it('maxRange move + 1', (done: Done) => {
    crypto.randomInt(1, MAX_RANGE + 1, () => {
      done()
    })
  })

  it('ERR_OUT_OF_RANGE 1', () => {
    assert.throws(
      () => crypto.randomInt(1, MAX_RANGE + 2, () => {}),
      /ERR_OUT_OF_RANGE/,
      'The value of "max" is out of range. ' +
        `It must be <= ${MAX_RANGE}. ` +
        'Received 281_474_976_710_657'
    )
  })

  it('ERR_OUT_OF_RANGE 2', () => {
    assert.throws(
      () => crypto.randomInt(MAX_RANGE + 1, () => {}),
      /ERR_OUT_OF_RANGE/,
      'The value of "max" is out of range. ' +
        `It must be <= ${MAX_RANGE}. ` +
        'Received 281_474_976_710_656'
    )
  })
  ;[true, NaN, [], 10].forEach((val) => {
    it(`expect type error: ${val}`, () => {
      assert.throws(
        () => crypto.randomInt(0, 1, val),
        /callback must be a function or undefined/
      )
    })
  })

  it('int16', (done: Done) => {
    crypto.randomFill(new Uint16Array(10), 0, () => {
      done()
    })
  })

  it('int32', (done: Done) => {
    crypto.randomFill(new Uint32Array(10), 0, () => {
      done()
    })
  })

  it('int32, 1', (done: Done) => {
    crypto.randomFill(new Uint32Array(10), 0, 1, () => {
      done()
    })
  })
})
