/* eslint-disable @typescript-eslint/no-unused-expressions */
import { test, assertThrowsAsync } from '../util';
import { expect } from 'chai';

import crypto, {
  ab2str,
  abvToArrayBuffer,
  Buffer,
} from 'react-native-quick-crypto';

// copied from https://github.com/nodejs/node/blob/master/test/parallel/test-crypto-random.js
const SUITE = 'random';

// --- Phase 4.5: fire-and-forget async assertion regression ---
//
// Pre-fix, every `crypto.randomFill(buf, (err, res) => { expect(...) })`
// call had its assertions silently swallowed: the test function returned
// before the callback fired, so a thrown AssertionError became an
// unhandled rejection rather than a test failure. The fix wraps each
// callback in a Promise the test function returns. The two tests below
// prove the pattern actually surfaces failures now.

test(SUITE, 'fire-and-forget regression: failing assert rejects the test', () =>
  assertThrowsAsync(
    () =>
      new Promise<void>((resolve, reject) => {
        const buf = Buffer.alloc(8);
        crypto.randomFill(buf, (err, _res) => {
          try {
            expect(err).to.be.null;
            expect(_res.length).to.equal(999); // intentionally wrong
            resolve();
          } catch (e) {
            reject(e);
          }
        });
      }),
    'expected', // chai assertion failure message contains "expected ..."
  ),
);

test(SUITE, 'simple test 1', () => {
  const buf = Buffer.alloc(10);
  const before = buf.toString('hex');
  const after = crypto.randomFillSync(buf).toString('hex');
  expect(before).not.to.equal(after);
});

test(SUITE, 'simple test 2', () => {
  const buf = new Uint8Array(new Array(10).fill(0));
  const before = Buffer.from(buf).toString('hex');
  crypto.randomFillSync(buf);
  const after = Buffer.from(buf).toString('hex');
  expect(before).not.to.equal(after);
});

test(SUITE, 'simple test 3', () => {
  [
    new Uint16Array(10),
    new Uint32Array(10),
    new Float32Array(10),
    new Float64Array(10),
    new DataView(new ArrayBuffer(10)),
  ].forEach(buf => {
    const before = Buffer.from(buf.buffer).toString('hex');
    crypto.randomFillSync(buf);
    const after = Buffer.from(buf.buffer).toString('hex');
    expect(before).not.to.equal(after);
  });
});

test(SUITE, 'simple test 4 - randomFillSync ArrayBuffer', () => {
  [new ArrayBuffer(10), new ArrayBuffer(10)].forEach(buf => {
    const before = Buffer.from(buf).toString('hex');
    crypto.randomFillSync(buf);
    const after = Buffer.from(buf).toString('hex');
    expect(before).not.to.equal(after);
  });
});

test(SUITE, 'simple test 5 - randomFill Buffer ', () => {
  const buf = Buffer.alloc(10);
  const before = buf.toString('hex');

  return new Promise<void>((resolve, reject) => {
    crypto.randomFill(buf, (err: Error | null, res: Buffer) => {
      try {
        expect(err).to.be.null;
        const after = res?.toString('hex');
        expect(before).not.to.equal(after);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
});

test(SUITE, 'simple test 6', () => {
  const buf = new Uint8Array(new Array(10).fill(0));
  const before = Buffer.from(buf).toString('hex');

  return new Promise<void>((resolve, reject) => {
    crypto.randomFill(buf, (err: Error | null, res: Uint8Array) => {
      try {
        expect(err).to.be.null;
        const after = Buffer.from(res).toString('hex');
        expect(before).not.to.equal(after);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
});

type BufTypes =
  | Uint16Array
  | Uint32Array
  | Float32Array
  | Float64Array
  | DataView;
const bufs: [BufTypes, string][] = [
  [new Uint16Array(10), 'Uint16Array'],
  [new Uint32Array(10), 'Uint32Array'],
  [new Float32Array(10), 'Float32Array'],
  [new Float64Array(10), 'Float64Array'],
  [new DataView(new ArrayBuffer(10)), 'DataView'],
];
bufs.forEach(([buf, name]) => {
  test(SUITE, `simple test 7, ${name}`, () => {
    const ab = abvToArrayBuffer(buf);
    const before = ab2str(ab);

    return new Promise<void>((resolve, reject) => {
      crypto.randomFill(ab, (err: Error | null, buf2: ArrayBuffer) => {
        try {
          expect(err).to.be.null;
          const after = Buffer.from(buf2).toString('hex');
          expect(before).not.to.equal(after);
          resolve();
        } catch (e) {
          reject(e);
        }
      });
    });
  });
});

test(SUITE, 'simple test 8', () => {
  // Two ArrayBuffers, two callbacks — resolve only when both have asserted.
  return Promise.all(
    [new ArrayBuffer(10), new ArrayBuffer(10)].map(
      buf =>
        new Promise<void>((resolve, reject) => {
          const before = Buffer.from(buf).toString('hex');
          crypto.randomFill(buf, (err: Error | null, res: ArrayBuffer) => {
            try {
              expect(err).to.be.null;
              const after = Buffer.from(res).toString('hex');
              expect(before).not.to.equal(after);
              resolve();
            } catch (e) {
              reject(e);
            }
          });
        }),
    ),
  ).then(() => {});
});

test(SUITE, 'randomFillSync - deepStringEqual - Buffer', () => {
  const buf = Buffer.alloc(10);
  const before = buf.toString('hex');
  crypto.randomFillSync(buf, 5, 5);
  const after = buf.toString('hex');
  expect(before).not.to.equal(after);
  expect(before.slice(0, 5)).to.equal(after.slice(0, 5));
});

test(SUITE, 'randomFillSync - deepStringEqual - Uint8Array', () => {
  const buf = new Uint8Array(new Array(10).fill(0));
  const before = Buffer.from(buf).toString('hex');
  crypto.randomFillSync(buf, 5, 5);
  const after = Buffer.from(buf).toString('hex');
  expect(before).not.to.equal(after);
  expect(before.slice(0, 5)).to.equal(after.slice(0, 5));
});

test(SUITE, 'randomFillSync - deepStringEqual - Buffer no size', () => {
  const buf = Buffer.alloc(10);
  const before = buf.toString('hex');
  crypto.randomFillSync(buf, 5);
  const after = buf.toString('hex');
  expect(before).not.to.equal(after);
  expect(before.slice(0, 5)).to.equal(after.slice(0, 5));
});

test(SUITE, 'randomFill - deepStringEqual - Buffer', () => {
  const buf = Buffer.alloc(10);
  const before = buf.toString('hex');

  return new Promise<void>((resolve, reject) => {
    crypto.randomFill(buf, 5, 5, (err: Error | null, res: Buffer) => {
      try {
        expect(err).to.be.null;
        const after = Buffer.from(res).toString('hex');
        expect(before).not.to.equal(after);
        expect(before.slice(0, 5)).to.equal(after.slice(0, 5));
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
});

test(SUITE, 'randomFill - deepStringEqual - Uint8Array', () => {
  const buf = new Uint8Array(new Array(10).fill(0));
  const before = Buffer.from(buf).toString('hex');
  return new Promise<void>((resolve, reject) => {
    crypto.randomFill(buf, 5, 5, (err: Error | null, res: Uint8Array) => {
      try {
        expect(err).to.be.null;
        const after = Buffer.from(res).toString('hex');
        expect(before).not.to.equal(after);
        expect(before.slice(0, 5)).to.equal(after.slice(0, 5));
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
});

//   finish
// describe('errors checks', () => {
//   [Buffer.alloc(10), new Uint8Array(new Array(10).fill(0))].forEach((buf) => {
//     const buffer = buf;
//     test(SUITE, 'Expected byteLength of 10', () => {
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

//     test(SUITE, 'offset must be a number', () => {
//       assert.throws(
//         () => crypto.randomFillSync(buffer, 'test'),
//         /ERR_INVALID_ARG_TYPE/,
//         typeErrObj.message
//       );
//     });

//     test(SUITE, 'offsetMustBe a number ', () => {
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

// Note: randomBytes & pseudoRandomBytes are equivalent (as of now), so this
//       will only run "lengths" number of tests, not 2 x "lengths"
[crypto.randomBytes, crypto.pseudoRandomBytes].map(fn => {
  [0, 1, 2, 4, 16, 256, 1024, 101.2].map(len => {
    test(SUITE, `${fn.name} @ ${len}`, () => {
      return new Promise<void>((resolve, reject) => {
        fn(len, (ex: Error | null, buf?: Buffer) => {
          try {
            expect(ex).to.be.null;
            expect(buf?.length).to.equal(Math.floor(len));
            expect(Buffer.isBuffer(buf)).to.be.true;
            resolve();
          } catch (e) {
            reject(e);
          }
        });
      });
    });
  });
});

['pseudoRandomBytes', 'prng', 'rng'].forEach(name => {
  test(SUITE, name, () => {
    const desc = Object.getOwnPropertyDescriptor(crypto, name);
    expect(desc).to.not.be.undefined;
    expect(desc?.configurable).to.be.true;
    // expect(desc?.enumerable).to.be.false;
  });
});

test(SUITE, 'randomInt - Asynchronous API', () => {
  return new Promise<void>((resolve, reject) => {
    const randomInts: number[] = [];
    let settled = false;
    const reportFail = (e: unknown) => {
      if (!settled) {
        settled = true;
        reject(e);
      }
    };
    for (let i = 0; i < 100; i++) {
      crypto.randomInt(3, (err: Error | null, n: number) => {
        if (settled) return;
        try {
          expect(err).to.be.null;
          expect(n).to.be.greaterThanOrEqual(0);
          expect(n).to.be.lessThan(3);
          randomInts.push(n);
          if (randomInts.length === 100) {
            expect(randomInts).not.to.contain(-1);
            expect(randomInts).to.contain(0);
            expect(randomInts).to.contain(1);
            expect(randomInts).to.contain(2);
            expect(randomInts).not.to.contain(3);
            settled = true;
            resolve();
          }
        } catch (e) {
          reportFail(e);
        }
      });
    }
  });
});

test(SUITE, 'randomInt - Synchronous API', () => {
  const randomInts = [];
  for (let i = 0; i < 100; i++) {
    const n = crypto.randomInt(3);
    expect(n).to.be.greaterThanOrEqual(0);
    expect(n).to.be.lessThan(3);
    randomInts.push(n);
  }

  expect(randomInts).not.to.contain(-1);
  expect(randomInts).to.contain(0);
  expect(randomInts).to.contain(1);
  expect(randomInts).to.contain(2);
  expect(randomInts).not.to.contain(3);
});

test(SUITE, 'randomInt positive range', () => {
  return new Promise<void>((resolve, reject) => {
    const randomInts: number[] = [];
    let settled = false;
    for (let i = 0; i < 100; i++) {
      crypto.randomInt(1, 3, (err: Error | null, n: number) => {
        if (settled) return;
        try {
          expect(err).to.be.null;
          expect(n).to.be.greaterThanOrEqual(1);
          expect(n).to.be.lessThan(3);
          randomInts.push(n);
          if (randomInts.length === 100) {
            expect(randomInts).to.contain(1);
            expect(randomInts).to.contain(2);
            settled = true;
            resolve();
          }
        } catch (e) {
          settled = true;
          reject(e);
        }
      });
    }
  });
});

test(SUITE, 'randomInt negative range', () => {
  return new Promise<void>((resolve, reject) => {
    const randomInts: number[] = [];
    let settled = false;
    for (let i = 0; i < 100; i++) {
      crypto.randomInt(-10, -8, (err: Error | null, n: number) => {
        if (settled) return;
        try {
          expect(err).to.be.null;
          expect(n).to.be.greaterThanOrEqual(-10);
          expect(n).to.be.lessThan(-8);
          randomInts.push(n);
          if (randomInts.length === 100) {
            expect(randomInts).not.to.contain(-11);
            expect(randomInts).to.contain(-10);
            expect(randomInts).to.contain(-9);
            expect(randomInts).not.to.contain(-8);
            settled = true;
            resolve();
          }
        } catch (e) {
          settled = true;
          reject(e);
        }
      });
    }
  });
});

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

for (const interval of [[0], [1, 1], [3, 2], [-5, -5], [11, -10]]) {
  test(SUITE, 'range ' + interval.toString(), () => {
    expect(() => {
      crypto.randomInt(1, MAX_RANGE + 2, () => {});
    }).to.throw(
      /ERR_OUT_OF_RANGE/,
      'The value of "max" is out of range. It must be greater than ' +
        `the value of "min" (${interval[interval.length - 2] || 0}). ` +
        `Received ${interval[interval.length - 1]}`,
    );
  });
}

const MAX_RANGE = 0xffffffffffff;
const maxInt = Number.MAX_SAFE_INTEGER;
const minInt = Number.MIN_SAFE_INTEGER;

test(SUITE, 'minInt, minInt + 5 ', () => {
  crypto.randomInt(minInt, minInt + 5, () => {
    // done();
  });
});

test(SUITE, 'maxint - 5, maxint', () => {
  crypto.randomInt(maxInt - 5, maxInt, () => {
    // done();
  });
});

test(SUITE, 'randomInt 1', () => {
  crypto.randomInt(1, () => {
    // done();
  });
});

test(SUITE, 'randomInt 0 - 1', () => {
  crypto.randomInt(0, 1, () => {
    // done();
  });
});

test(SUITE, 'maxRange', () => {
  crypto.randomInt(MAX_RANGE, () => {
    // done();
  });
});

test(SUITE, 'maxRange move + 1', () => {
  crypto.randomInt(1, MAX_RANGE + 1, () => {
    // done();
  });
});

test(SUITE, 'ERR_OUT_OF_RANGE 1', () => {
  expect(() => {
    crypto.randomInt(1, MAX_RANGE + 2, () => {});
  }).to.throw(
    /ERR_OUT_OF_RANGE/,
    'The value of "max" is out of range. ' +
      `It must be <= ${MAX_RANGE}. ` +
      'Received 281_474_976_710_657',
  );
});

test(SUITE, 'ERR_OUT_OF_RANGE 2', () => {
  expect(() => {
    crypto.randomInt(MAX_RANGE + 1, () => {});
  }).to.throw(
    /ERR_OUT_OF_RANGE/,
    'The value of "max" is out of range. ' +
      `It must be <= ${MAX_RANGE}. ` +
      'Received 281_474_976_710_656',
  );
});

[true, NaN, [], 10].forEach(val => {
  test(SUITE, `expect type error: ${val}`, () => {
    expect(() => {
      // @ts-expect-error - testing bad args
      crypto.randomInt(0, 1, val);
    }).to.throw(/callback must be a function or undefined/);
  });
});

test(SUITE, 'randomFill int16', () => {
  crypto.randomFill(new Uint16Array(10), 0, () => {
    // done();
  });
});

test(SUITE, 'randomFill int32', () => {
  crypto.randomFill(new Uint32Array(10), 0, () => {
    // done();
  });
});

test(SUITE, 'randomFill int32, 1', () => {
  crypto.randomFill(new Uint32Array(10), 0, 1, () => {
    // done();
  });
});

test(SUITE, 'crypto.getRandomValues', () => {
  const r = crypto.getRandomValues(new Uint8Array(10));
  expect(r.length).to.equal(10);
});

// WebCrypto §getRandomValues: byteLength > 65536 must throw a
// QuotaExceededError DOMException carrying `quota` and `requested`.
test(SUITE, 'getRandomValues - QuotaExceededError on > 65536 bytes', () => {
  let caught: unknown;
  try {
    crypto.getRandomValues(new Uint8Array(65537));
  } catch (e) {
    caught = e;
  }
  const err = caught as Error & { quota?: number; requested?: number };
  expect(err).to.be.instanceOf(Error);
  expect(err.name).to.equal('QuotaExceededError');
  expect(err.quota).to.equal(65536);
  expect(err.requested).to.equal(65537);
});

// WebCrypto §getRandomValues: non-integer-typed views must throw
// TypeMismatchError. Float and DataView are explicitly excluded.
[
  ['Float32Array', () => new Float32Array(4)],
  ['Float64Array', () => new Float64Array(4)],
  ['DataView', () => new DataView(new ArrayBuffer(8))],
].forEach(([name, make]) => {
  test(SUITE, `getRandomValues - TypeMismatchError on ${name}`, () => {
    let caught: unknown;
    try {
      // @ts-expect-error - intentionally passing disallowed view type
      crypto.getRandomValues((make as () => ArrayBufferView)());
    } catch (e) {
      caught = e;
    }
    const err = caught as Error;
    expect(err).to.be.instanceOf(Error);
    expect(err.name).to.equal('TypeMismatchError');
  });
});

// Issue #953: TypedArray views over larger ArrayBuffers
// getRandomValues / randomFillSync should only fill the view, not the entire
// underlying ArrayBuffer.

test(
  SUITE,
  'getRandomValues - view over larger buffer preserves surrounding data',
  () => {
    const heap = new ArrayBuffer(1024);
    const full = new Uint8Array(heap);
    full.fill(42);

    const view = new Uint8Array(heap, 100, 32);
    crypto.getRandomValues(view);

    // Bytes before the view must be untouched
    expect(full[0]).to.equal(42);
    expect(full[99]).to.equal(42);
    // Bytes after the view must be untouched
    expect(full[132]).to.equal(42);
    expect(full[1023]).to.equal(42);
    // The view itself must have been randomized (not still all 42)
    const viewStillAll42 = view.every(b => b === 42);
    expect(viewStillAll42).to.be.false;
  },
);

test(
  SUITE,
  'randomFillSync - view over larger buffer preserves surrounding data',
  () => {
    const heap = new ArrayBuffer(1024);
    const full = new Uint8Array(heap);
    full.fill(42);

    const view = new Uint8Array(heap, 200, 64);
    crypto.randomFillSync(view);

    expect(full[0]).to.equal(42);
    expect(full[199]).to.equal(42);
    expect(full[264]).to.equal(42);
    expect(full[1023]).to.equal(42);
    // The view itself must have been randomized
    const viewStillAll42 = view.every(b => b === 42);
    expect(viewStillAll42).to.be.false;
  },
);

test(SUITE, 'randomFillSync - view with offset and size params', () => {
  const heap = new ArrayBuffer(512);
  const full = new Uint8Array(heap);
  full.fill(42);

  // View starts at byte 100, length 64
  // randomFillSync offset=10, size=20 → should fill view bytes 10-29,
  // i.e. heap bytes 110-129 only
  const view = new Uint8Array(heap, 100, 64);
  crypto.randomFillSync(view, 10, 20);

  // Within the view but before the offset — these must stay 42
  // With the bug, offset is applied to the underlying buffer (byte 10)
  // instead of relative to the view (byte 110), so byte 10 gets randomized
  // while bytes 100-109 stay 42 by accident. Check byte 10 to catch this.
  expect(full[10]).to.equal(42);
  expect(full[29]).to.equal(42);
  // View bytes before the offset (heap 100-109) must be untouched
  expect(full[100]).to.equal(42);
  expect(full[109]).to.equal(42);
  // The filled region (heap 110-129) must have been randomized
  const filled = full.slice(110, 130);
  const filledStillAll42 = filled.every(b => b === 42);
  expect(filledStillAll42).to.be.false;
});

test(
  SUITE,
  'randomFill (async) - view over larger buffer preserves surrounding data',
  () => {
    const heap = new ArrayBuffer(1024);
    const full = new Uint8Array(heap);
    full.fill(42);

    const view = new Uint8Array(heap, 100, 32);
    return new Promise<void>((resolve, reject) => {
      crypto.randomFill(view, (err: Error | null) => {
        try {
          expect(err).to.be.null;
          expect(full[0]).to.equal(42);
          expect(full[99]).to.equal(42);
          expect(full[132]).to.equal(42);
          expect(full[1023]).to.equal(42);
          const viewStillAll42 = view.every(b => b === 42);
          expect(viewStillAll42).to.be.false;
          resolve();
        } catch (e) {
          reject(e);
        }
      });
    });
  },
);

// --- randomUUID (RFC 9562 §5.4 — v4) ---

const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

test(SUITE, 'randomUUID returns RFC 9562 v4 string', () => {
  const id = crypto.randomUUID();
  expect(id).to.match(UUID_V4_RE);
});

test(SUITE, 'randomUUID accepts disableEntropyCache option', () => {
  const id = crypto.randomUUID({ disableEntropyCache: true });
  expect(id).to.match(UUID_V4_RE);
});

test(SUITE, 'randomUUID values are unique', () => {
  const ids = new Set<string>();
  for (let i = 0; i < 100; i++) ids.add(crypto.randomUUID());
  expect(ids.size).to.equal(100);
});

// --- randomUUIDv7 (RFC 9562 §5.7) ---

const UUID_V7_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function uuidV7Timestamp(id: string): number {
  // First 12 hex chars = 48-bit ms timestamp.
  return parseInt(id.replace(/-/g, '').slice(0, 12), 16);
}

test(SUITE, 'randomUUIDv7 returns RFC 9562 v7 string', () => {
  const id = crypto.randomUUIDv7();
  expect(id).to.match(UUID_V7_RE);
});

test(SUITE, 'randomUUIDv7 version=7 and variant=10', () => {
  const id = crypto.randomUUIDv7();
  const hex = id.replace(/-/g, '');
  expect(parseInt(hex[12]!, 16)).to.equal(7);
  // variant nibble: top 2 bits must be 10xx, i.e. 8/9/a/b
  const v = parseInt(hex[16]!, 16);
  expect(v >= 0x8 && v <= 0xb).to.equal(true);
});

test(SUITE, 'randomUUIDv7 timestamp matches Date.now()', () => {
  const before = Date.now();
  const id = crypto.randomUUIDv7();
  const after = Date.now();
  const ts = uuidV7Timestamp(id);
  expect(ts >= before && ts <= after).to.equal(true);
});

test(SUITE, 'randomUUIDv7 timestamps are monotonic', () => {
  const ids: string[] = [];
  for (let i = 0; i < 50; i++) ids.push(crypto.randomUUIDv7());
  for (let i = 1; i < ids.length; i++) {
    expect(uuidV7Timestamp(ids[i]!) >= uuidV7Timestamp(ids[i - 1]!)).to.equal(
      true,
    );
  }
});

test(SUITE, 'randomUUIDv7 accepts disableEntropyCache option', () => {
  const id = crypto.randomUUIDv7({ disableEntropyCache: true });
  expect(id).to.match(UUID_V7_RE);
});

test(SUITE, 'randomUUIDv7 values are unique', () => {
  const ids = new Set<string>();
  for (let i = 0; i < 100; i++) ids.add(crypto.randomUUIDv7());
  expect(ids.size).to.equal(100);
});
