import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import {
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const RUNNER = path.join(TEST_DIR, 'runner.mjs');

test(
  'actual runner recovers and deletes an iOS device interrupted during create',
  { timeout: 30_000 },
  async context => {
    for (const signal of ['SIGINT', 'SIGTERM']) {
      await context.test(signal, async () => runInterruption(signal));
    }
  },
);

async function runInterruption(signal) {
  const directory = await mkdtemp(path.join(tmpdir(), 'rnqc-runner-boundary-'));
  const bin = path.join(directory, 'bin');
  const state = path.join(directory, 'simulator.json');
  const deleted = path.join(directory, 'deleted.json');
  const artifacts = path.join(directory, 'artifacts');
  await mkdir(bin);
  await writeMocks(bin);

  const child = spawn(
    process.execPath,
    [RUNNER, '--platform', 'ios', '--skip-build', '--artifacts-dir', artifacts],
    {
      env: {
        ...process.env,
        PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}`,
        RNQC_MOCK_SIMULATOR_STATE: state,
        RNQC_MOCK_SIMULATOR_DELETED: deleted,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  const stdout = [];
  const stderr = [];
  child.stdout.on('data', chunk => stdout.push(chunk));
  child.stderr.on('data', chunk => stderr.push(chunk));

  try {
    await waitForFile(state, child);
    child.kill(signal);
    const completion = await waitForExit(child);
    assert.equal(completion.signal, null);
    assert.equal(completion.exitCode, signal === 'SIGINT' ? 130 : 143);

    const createdDevice = JSON.parse(await readFile(deleted, 'utf8'));
    assert.match(createdDevice.name, /^rnqc-e2e-/);
    assert.equal(createdDevice.id, '00000000-0000-0000-0000-000000000001');
    assert.equal(existsSync(state), false);

    const result = JSON.parse(
      await readFile(path.join(artifacts, 'result.json'), 'utf8'),
    );
    assert.equal(result.status, 'infrastructure_failure');
    assert.equal(result.error.name, 'SignalInterruptionError');
    assert.equal(result.error.signal, signal);
    assert.equal(result.device.name, createdDevice.name);
    assert.equal(result.device.id, createdDevice.id);
    assert.equal(result.cleanupErrors, undefined);
    assert.match(
      Buffer.concat(stdout).toString('utf8'),
      /ARTIFACT_SHA256 sha256=[a-f0-9]{64} path=.*result\.json/,
    );
  } catch (error) {
    error.message += `\nrunner stderr:\n${Buffer.concat(stderr).toString('utf8')}`;
    throw error;
  } finally {
    if (child.exitCode === null && child.signalCode === null)
      child.kill('SIGKILL');
    await rm(directory, { recursive: true, force: true });
  }
}

async function writeMocks(bin) {
  await writeExecutable(
    path.join(bin, 'bundle'),
    `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === '--version') console.log('Bundler version 2.5.23');
else if (args[0] === 'check') console.log("The Gemfile's dependencies are satisfied");
else if (args[0] === 'exec' && args[1] === 'pod' && args[2] === '--version') console.log('1.15.2');
else if (args[0] === 'exec' && args[1] === 'pod') console.log('Pod installation complete!');
else process.exit(2);
`,
  );
  await writeExecutable(
    path.join(bin, 'ruby'),
    `#!/usr/bin/env node
console.log('ruby 3.4.3 mock');
`,
  );
  await writeExecutable(
    path.join(bin, 'xcodebuild'),
    `#!/usr/bin/env node
console.log('Xcode 26.2\\nBuild version mock');
`,
  );
  await writeExecutable(
    path.join(bin, 'xcrun'),
    `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
const statePath = process.env.RNQC_MOCK_SIMULATOR_STATE;
const deletedPath = process.env.RNQC_MOCK_SIMULATOR_DELETED;
const id = '00000000-0000-0000-0000-000000000001';
if (args.join(' ') === 'simctl list runtimes -j') {
  console.log(JSON.stringify({ runtimes: [{ identifier: 'com.apple.CoreSimulator.SimRuntime.iOS-26-2', version: '26.2', isAvailable: true, supportedDeviceTypes: [{ identifier: 'com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro', name: 'iPhone 17 Pro', productFamily: 'iPhone' }] }] }));
} else if (args[0] === 'simctl' && args[1] === 'create') {
  const device = { name: args[2], id };
  fs.writeFileSync(statePath, JSON.stringify(device));
  process.stdout.write(id + '\\n');
  setInterval(() => {}, 1000);
} else if (args.join(' ') === 'simctl list devices -j') {
  const devices = fs.existsSync(statePath) ? [JSON.parse(fs.readFileSync(statePath, 'utf8'))] : [];
  console.log(JSON.stringify({ devices: { mock: devices.map(device => ({ name: device.name, udid: device.id, state: 'Shutdown', isAvailable: true })) } }));
} else if (args[0] === 'simctl' && args[1] === 'shutdown') {
  process.exit(0);
} else if (args[0] === 'simctl' && args[1] === 'delete') {
  const device = JSON.parse(fs.readFileSync(statePath, 'utf8'));
  if (args[2] !== device.id) process.exit(3);
  fs.writeFileSync(deletedPath, JSON.stringify(device));
  fs.unlinkSync(statePath);
} else {
  process.exit(2);
}
`,
  );
}

async function writeExecutable(file, contents) {
  await writeFile(file, contents);
  await chmod(file, 0o755);
}

async function waitForFile(file, child) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (existsSync(file)) return;
    if (child.exitCode !== null || child.signalCode !== null)
      throw new Error('Runner exited before mock simulator creation');
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error('Timed out waiting for mock simulator creation');
}

async function waitForExit(child) {
  if (child.exitCode !== null || child.signalCode !== null)
    return { exitCode: child.exitCode, signal: child.signalCode };
  return await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (exitCode, signal) => resolve({ exitCode, signal }));
  });
}
