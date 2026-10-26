import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';

import {
  ResourceRegistry,
  finalizeRun,
  installSignalShutdown,
  waitForChildExit,
} from './runner-lifecycle.mjs';

class MockChild extends EventEmitter {
  constructor() {
    super();
    this.exitCode = null;
    this.signalCode = null;
    this.signals = [];
  }

  kill(signal) {
    this.signals.push(signal);
    this.signalCode = signal;
    queueMicrotask(() => this.emit('close', null, signal));
    return true;
  }
}

test('partial resources remain registered for cleanup after setup faults', () => {
  const registry = new ResourceRegistry({ session: 'test' });
  const device = registry.registerDevice({ id: 'owned-device' });
  const metro = registry.registerMetro({ child: new MockChild() });

  assert.equal(registry.device, device);
  assert.equal(registry.metro, metro);
});

test('active child termination is idempotent', async () => {
  const registry = new ResourceRegistry({ session: 'test' });
  const child = registry.trackChild(new MockChild());

  registry.terminateActive();
  registry.terminateActive();
  await new Promise(resolve => child.once('close', resolve));

  assert.deepEqual(child.signals, ['SIGTERM']);
  assert.equal(registry.activeChildren.size, 0);
});

test('a watched emulator exit terminates and reaps adb wait', async () => {
  const adb = new MockChild();
  const emulator = new MockChild();
  const waiting = waitForChildExit(adb, {
    watchedChild: emulator,
    timeoutMs: 1_000,
    watchedChildMessage: 'emulator exited',
  });

  emulator.exitCode = 1;
  emulator.emit('exit', 1, null);

  await assert.rejects(waiting, /emulator exited \(exit=1, signal=null\)/);
  assert.deepEqual(adb.signals, ['SIGTERM']);
  assert.equal(adb.listenerCount('close'), 0);
});

test('a timed out child is terminated and reaped', async () => {
  const child = new MockChild();

  await assert.rejects(
    waitForChildExit(child, {
      timeoutMs: 5,
      timeoutMessage: 'bounded wait expired',
    }),
    /bounded wait expired/,
  );
  assert.deepEqual(child.signals, ['SIGTERM']);
  assert.equal(child.listenerCount('close'), 0);
});

test('signal shutdown is idempotent and preserves finalization', () => {
  const processTarget = new EventEmitter();
  const signals = [];
  const shutdown = installSignalShutdown(processTarget, signal =>
    signals.push(signal),
  );

  processTarget.emit('SIGINT');
  processTarget.emit('SIGTERM');
  assert.deepEqual(signals, ['SIGINT']);
  assert.equal(shutdown.signal, 'SIGINT');
  assert.equal(shutdown.exitCode, 130);
  assert.throws(() => shutdown.throwIfRequested(), /interrupted by SIGINT/);

  shutdown.beginFinalization();
  shutdown.dispose();
  assert.equal(processTarget.listenerCount('SIGINT'), 0);
  assert.equal(processTarget.listenerCount('SIGTERM'), 0);
});

test('a signal first received during finalization does not cancel cleanup', () => {
  const processTarget = new EventEmitter();
  let cancellations = 0;
  const shutdown = installSignalShutdown(processTarget, () => cancellations++);

  shutdown.beginFinalization();
  processTarget.emit('SIGTERM');

  assert.equal(shutdown.signal, 'SIGTERM');
  assert.equal(shutdown.exitCode, 143);
  assert.equal(cancellations, 0);
  assert.doesNotThrow(() => shutdown.throwIfRequested());
  shutdown.dispose();
});

test('cancellation still runs cleanup and writes a failing artifact', async () => {
  const processTarget = new EventEmitter();
  const shutdown = installSignalShutdown(processTarget, () => {});
  const calls = [];
  const result = { status: 'passed' };
  processTarget.emit('SIGTERM');

  await finalizeRun(
    shutdown,
    async () => calls.push('cleanup'),
    async signal => {
      result.status = signal ? 'infrastructure_failure' : result.status;
      result.signal = signal;
      calls.push('artifact');
    },
  );

  assert.deepEqual(calls, ['cleanup', 'artifact']);
  assert.deepEqual(result, {
    status: 'infrastructure_failure',
    signal: 'SIGTERM',
  });
  shutdown.dispose();
});
