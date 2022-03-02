import type { TestResult } from './TestResult';
import { rootSuite } from './MochaRNAdapter';
import 'mocha';
import type * as MochaTypes from 'mocha';
import { pbkdf2RegisterTests } from './pbkdf2Tests/pbkdf2Tests';

export async function testLib(addTestResult: (testResult: TestResult) => void) {
  console.log('setting up mocha');

  const {
    EVENT_RUN_BEGIN,
    EVENT_RUN_END,
    EVENT_TEST_FAIL,
    EVENT_TEST_PASS,
    EVENT_SUITE_BEGIN,
    EVENT_SUITE_END,
  } = Mocha.Runner.constants;

  var runner = new Mocha.Runner(rootSuite) as MochaTypes.Runner;

  let indents = 0;
  const indent = () => Array(indents).join('  ');
  runner
    .once(EVENT_RUN_BEGIN, () => {})
    .on(EVENT_SUITE_BEGIN, () => {
      indents++;
    })
    .on(EVENT_SUITE_END, () => {
      indents--;
    })
    .on(EVENT_TEST_PASS, (test: MochaTypes.Runnable) => {
      addTestResult({
        name: test.fullTitle(),
        key: Math.random().toString(),
        status: 'correct',
      });
      console.log(`${indent()}pass: ${test.fullTitle()}`);
    })
    .on(EVENT_TEST_FAIL, (test: MochaTypes.Runnable, err: Error) => {
      addTestResult({
        name: test.fullTitle(),
        key: Math.random().toString(),
        status: 'incorrect',
        errorMsg: err.message,
      });
      console.log(
        `${indent()}fail: ${test.fullTitle()} - error: ${err.message}`
      );
    })
    .once(EVENT_RUN_END, () => {});

  pbkdf2RegisterTests();
  //HmacTests.add();

  runner.run();
}
