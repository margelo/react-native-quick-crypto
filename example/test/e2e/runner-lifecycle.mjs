const SIGNAL_EXIT_CODES = { SIGINT: 130, SIGTERM: 143 };

export class ResourceRegistry {
  constructor(initial) {
    Object.assign(this, initial);
    this.activeChildren = new Map();
  }

  registerDevice(device) {
    this.device = device;
    return device;
  }

  registerMetro(metro) {
    this.metro = metro;
    return metro;
  }

  trackChild(child, options = {}) {
    const registration = { child, ...options, terminationRequested: false };
    this.activeChildren.set(child, registration);
    child.once('error', error => {
      child.spawnError = error;
    });
    child.once('close', () => {
      if (registration.killTimeout) clearTimeout(registration.killTimeout);
      this.activeChildren.delete(child);
    });
    return child;
  }

  terminateActive() {
    for (const registration of this.activeChildren.values()) {
      if (registration.terminationRequested) continue;
      registration.terminationRequested = true;
      terminateChild(registration.child, registration.detached);
      registration.killTimeout = setTimeout(() => {
        if (!hasExited(registration.child))
          terminateChild(registration.child, registration.detached, 'SIGKILL');
      }, 5_000);
    }
  }
}

export class SignalInterruptionError extends Error {
  constructor(signal) {
    super(`E2E run interrupted by ${signal}`);
    this.name = 'SignalInterruptionError';
    this.signal = signal;
  }
}

export function installSignalShutdown(processTarget, onSignal) {
  let requestedSignal;
  let finalizing = false;
  const handlers = new Map();
  for (const signal of Object.keys(SIGNAL_EXIT_CODES)) {
    const handler = () => {
      if (requestedSignal) return;
      requestedSignal = signal;
      if (!finalizing) onSignal(signal);
    };
    handlers.set(signal, handler);
    processTarget.on(signal, handler);
  }
  return {
    get signal() {
      return requestedSignal;
    },
    get exitCode() {
      return requestedSignal ? SIGNAL_EXIT_CODES[requestedSignal] : undefined;
    },
    beginFinalization() {
      finalizing = true;
    },
    throwIfRequested() {
      if (requestedSignal && !finalizing)
        throw new SignalInterruptionError(requestedSignal);
    },
    interruptionError() {
      return new SignalInterruptionError(requestedSignal);
    },
    dispose() {
      for (const [signal, handler] of handlers)
        processTarget.off(signal, handler);
    },
  };
}

export async function finalizeRun(signalShutdown, cleanup, writeArtifacts) {
  signalShutdown.beginFinalization();
  await cleanup();
  await writeArtifacts(signalShutdown.signal);
}

export async function waitForChildExit(
  child,
  {
    timeoutMs,
    watchedChild,
    timeoutMessage = `Child process did not exit within ${timeoutMs}ms`,
    watchedChildMessage = 'Dependency process exited before child completed',
    killGraceMs = 5_000,
  } = {},
) {
  if (hasExited(child))
    return { exitCode: child.exitCode, signal: child.signalCode };

  return await new Promise((resolve, reject) => {
    let failure;
    let timeout;
    let killTimeout;

    const cleanup = () => {
      if (timeout) clearTimeout(timeout);
      if (killTimeout) clearTimeout(killTimeout);
      child.off('error', onError);
      child.off('close', onClose);
      watchedChild?.off('exit', onWatchedExit);
      watchedChild?.off('error', onWatchedError);
    };
    const requestTermination = error => {
      if (failure) return;
      failure = error;
      terminateChild(child, false);
      killTimeout = setTimeout(() => {
        if (!hasExited(child)) child.kill('SIGKILL');
      }, killGraceMs);
    };
    const onError = error => {
      cleanup();
      reject(error);
    };
    const onClose = (exitCode, signal) => {
      cleanup();
      if (failure) {
        failure.exitCode = exitCode;
        failure.signal = signal;
        reject(failure);
      } else resolve({ exitCode, signal });
    };
    const onWatchedExit = (exitCode, signal) => {
      requestTermination(
        new Error(
          `${watchedChildMessage} (exit=${exitCode}, signal=${signal})`,
        ),
      );
    };
    const onWatchedError = error => {
      requestTermination(new Error(`${watchedChildMessage}: ${error.message}`));
    };

    child.once('error', onError);
    child.once('close', onClose);
    watchedChild?.once('exit', onWatchedExit);
    watchedChild?.once('error', onWatchedError);
    if (timeoutMs !== undefined) {
      timeout = setTimeout(
        () => requestTermination(new Error(timeoutMessage)),
        timeoutMs,
      );
    }
    if (watchedChild && hasExited(watchedChild))
      onWatchedExit(watchedChild.exitCode, watchedChild.signalCode);
    else if (watchedChild?.spawnError) onWatchedError(watchedChild.spawnError);
  });
}

function terminateChild(child, detached, signal = 'SIGTERM') {
  if (hasExited(child)) return;
  try {
    if (detached && child.pid) process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch {
    child.kill(signal);
  }
}

function hasExited(child) {
  return child.exitCode !== null || child.signalCode !== null;
}
