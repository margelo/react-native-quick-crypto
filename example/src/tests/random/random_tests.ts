/* eslint-disable @typescript-eslint/no-unused-expressions */
import { Buffer } from '@craftzdog/react-native-buffer';
import { test } from '../util';
import { expect } from 'chai';

import crypto, { ab2str, abvToArrayBuffer } from 'react-native-quick-crypto';

// copied from https://github.com/nodejs/node/blob/master/test/parallel/test-crypto-random.js
const SUITE = 'random';

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
  // done: Done
  const buf = Buffer.alloc(10);
  const before = buf.toString('hex');

  crypto.randomFill(buf, (_err: Error | null, res: Buffer) => {
    try {
      const after = res?.toString('hex');
      expect(before).not.to.equal(after);
      // done();
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (e) {
      // done(e);
    }
  });
});

test(SUITE, 'simple test 6', () => {
  // done: Done
  const buf = new Uint8Array(new Array(10).fill(0));
  const before = Buffer.from(buf).toString('hex');

  crypto.randomFill(buf, (_err: Error | null, res: Uint8Array) => {
    try {
      const after = Buffer.from(res).toString('hex');
      expect(before).not.to.equal(after);
      // done();
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (e) {
      // done(e);
    }
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
    // done: Done
    const ab = abvToArrayBuffer(buf);
    const before = ab2str(ab);

    crypto.randomFill(ab, (_err: Error | null, buf2: ArrayBuffer) => {
      try {
        const after = Buffer.from(buf2).toString('hex');
        expect(before).not.to.equal(after);
        // done();
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
      } catch (e) {
        // done(e);
      }
    });
  });
});

test(SUITE, 'simple test 8', () => {
  // done: Done
  let ctr = 0;
  [new ArrayBuffer(10), new ArrayBuffer(10)].forEach(buf => {
    const before = Buffer.from(buf).toString('hex');
    crypto.randomFill(buf, (_err: Error | null, res: ArrayBuffer) => {
      try {
        const after = Buffer.from(res).toString('hex');
        expect(before).not.to.equal(after);
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
      } catch (e) {
        // done(e);
      }
      ctr++;
      if (ctr === 2) {
        // done();
      }
    });
  });
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
  // done: Done
  const buf = Buffer.alloc(10);
  const before = buf.toString('hex');

  crypto.randomFill(buf, 5, 5, (_err: Error | null, res: Buffer) => {
    try {
      const after = Buffer.from(res).toString('hex');
      expect(before).not.to.equal(after);
      expect(before.slice(0, 5)).to.equal(after.slice(0, 5));
      // done();
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (e) {
      // done(e);
    }
  });
});

test(SUITE, 'randomFill - deepStringEqual - Uint8Array', () => {
  // done: Done
  const buf = new Uint8Array(new Array(10).fill(0));
  const before = Buffer.from(buf).toString('hex');
  crypto.randomFill(buf, 5, 5, (_err: Error | null, res: Uint8Array) => {
    try {
      const after = Buffer.from(res).toString('hex');
      expect(before).not.to.equal(after);
      expect(before.slice(0, 5)).to.equal(after.slice(0, 5));
      // done();
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (e) {
      // done(e);
    }
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
      expect(() => {
        fn(len, (ex: Error | null, buf?: Buffer) => {
          expect(ex).to.be.null;
          expect(buf?.length).to.equal(Math.floor(len));
          expect(Buffer.isBuffer(buf)).to.be.true;
        });
      }).to.not.throw();
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
  // done: Done
  const randomInts: number[] = [];
  let failed = false;
  for (let i = 0; i < 100; i++) {
    crypto.randomInt(3, (_err: Error | null, n: number) => {
      try {
        expect(n).to.be.greaterThanOrEqual(0);
        expect(n).to.be.lessThan(3);
        randomInts.push(n);
        if (randomInts.length === 100) {
          expect(randomInts).not.to.contain(-1);
          expect(randomInts).to.contain(0);
          expect(randomInts).to.contain(1);
          expect(randomInts).to.contain(2);
          expect(randomInts).not.to.contain(3);
          // done();
        }
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
      } catch (e) {
        if (!failed) {
          // done(e);
          failed = true;
        }
      }
    });
  }
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
  // done: Done
  const randomInts: number[] = [];
  let failed = false;
  for (let i = 0; i < 100; i++) {
    crypto.randomInt(1, 3, (_err: Error | null, n: number) => {
      try {
        expect(n).to.be.greaterThanOrEqual(1);
        expect(n).to.be.lessThan(3);
        randomInts.push(n);
        if (randomInts.length === 100) {
          expect(randomInts).to.contain(1);
          expect(randomInts).to.contain(2);
          // done();
        }
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
      } catch (e) {
        if (!failed) {
          // done(e);
          failed = true;
        }
      }
    });
  }
});

test(SUITE, 'randomInt negative range', () => {
  const randomInts: number[] = [];
  let failed = false;
  for (let i = 0; i < 100; i++) {
    crypto.randomInt(-10, -8, (_err: Error | null, n: number) => {
      try {
        expect(n).to.be.greaterThanOrEqual(-10);
        expect(n).to.be.lessThan(-8);
        randomInts.push(n);
        if (randomInts.length === 100) {
          expect(randomInts).not.to.contain(-11);
          expect(randomInts).to.contain(-10);
          expect(randomInts).to.contain(-9);
          expect(randomInts).not.to.contain(-8);
          // done();
        }
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
      } catch (e) {
        if (!failed) {
          // done(e);
          failed = true;
        }
      }
    });
  }
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
