#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  createWriteStream,
  existsSync,
  readFileSync,
  readdirSync,
} from 'node:fs';
import {
  copyFile,
  mkdir,
  readFile,
  readdir,
  writeFile,
} from 'node:fs/promises';
import { createServer } from 'node:net';
import { homedir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import {
  ResourceRegistry,
  finalizeRun,
  installSignalShutdown,
  waitForChildExit,
} from './runner-lifecycle.mjs';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const EXAMPLE_DIR = path.resolve(SCRIPT_DIR, '../..');
const REPO_DIR = path.resolve(EXAMPLE_DIR, '..');
const APP_ID = 'com.margelo.quickcrypto.example';
const APP_NAME = 'QuickCryptoExample';
const AGENT_DEVICE = path.join(EXAMPLE_DIR, 'node_modules/.bin/agent-device');
const RESULT_PATTERN =
  /^E2E_RESULT status=(passed|failed) suites=(\d+) failed_suites=(\d+) tests=(\d+) failures=(\d+) duration_ms=(\d+)$/;

const options = parseArgs(process.argv.slice(2));
const startedAt = new Date();
const runId = `${startedAt.toISOString().replaceAll(/[:.]/g, '-')}-${process.pid}`;
const artifactsDir = path.resolve(
  options.artifactsDir ??
    path.join(EXAMPLE_DIR, 'build/e2e', options.platform, runId),
);
const commands = [];
let iosToolchain;
const owned = new ResourceRegistry({
  metro: undefined,
  device: undefined,
  session: `rnqc-e2e-${runId}`,
  sessionOpened: false,
  agentUsed: false,
});
let result = {
  schemaVersion: 1,
  status: 'infrastructure_failure',
  platform: options.platform,
  revision: {},
  startedAt: startedAt.toISOString(),
  completedAt: undefined,
  durationMs: undefined,
  toolVersions: {},
  device: undefined,
  build: undefined,
  summary: undefined,
  artifacts: {},
  commands,
  error: undefined,
};

await mkdir(artifactsDir, { recursive: true });
result.artifacts = {
  directory: artifactsDir,
  result: path.join(artifactsDir, 'result.json'),
  metroLog: path.join(artifactsDir, 'metro.log'),
  buildLog: path.join(artifactsDir, `${options.platform}-build.log`),
  deviceLog: path.join(artifactsDir, `${options.platform}-device.log`),
  screenshot: path.join(artifactsDir, `${options.platform}-test-result.png`),
  ...(options.platform === 'android'
    ? { lintReport: path.join(artifactsDir, 'android-lint.xml') }
    : { podsLog: path.join(artifactsDir, 'ios-pods.log') }),
  agentDevice: path.join(artifactsDir, 'agent-device'),
};
await mkdir(result.artifacts.agentDevice, { recursive: true });
const signalShutdown = installSignalShutdown(process, () =>
  owned.terminateActive(),
);

try {
  assertPrerequisites();
  result.revision = await revision();
  if (options.platform === 'ios') iosToolchain = await bootstrapIosPods();
  result.toolVersions = await toolVersions();

  owned.device =
    options.platform === 'ios'
      ? await createIosSimulator()
      : await createAndroidEmulator();
  result.device = owned.device.evidence;

  result.build =
    options.platform === 'ios'
      ? await buildIos(owned.device)
      : await buildAndroid(owned.device);

  const metroPort = await availablePort();
  owned.metro = await startMetro(metroPort);
  if (options.platform === 'android') {
    await command(androidTool('adb'), [
      '-s',
      owned.device.id,
      'reverse',
      `tcp:${metroPort}`,
      `tcp:${metroPort}`,
    ]);
    await command(androidTool('adb'), ['-s', owned.device.id, 'logcat', '-c']);
  }

  await installApp(owned.device, result.build.appPath);
  const summary = await runSuite(owned.device, metroPort);
  result.summary = summary;
  result.status = summary.status === 'passed' ? 'passed' : 'failed';
} catch (error) {
  result.error = serializeError(error);
} finally {
  try {
    await finalizeRun(
      signalShutdown,
      async () => {
        await captureFailureScreenshot().catch(recordCleanupError);
        await collectDeviceLog().catch(recordCleanupError);
        await closeSession().catch(recordCleanupError);
        await stopAgentDaemon().catch(recordCleanupError);
        await stopMetro().catch(recordCleanupError);
        await destroyOwnedDevice().catch(recordCleanupError);
      },
      async signal => {
        result.completedAt = new Date().toISOString();
        result.durationMs = Date.now() - startedAt.valueOf();
        result.device ??= owned.device?.evidence;
        if (signal) {
          result.status = 'infrastructure_failure';
          result.error = serializeError(signalShutdown.interruptionError());
        }
        await writeFile(
          result.artifacts.result,
          `${JSON.stringify(result, null, 2)}\n`,
        );
        process.stdout.write(`E2E result: ${result.artifacts.result}\n`);
        process.stdout.write(`E2E status: ${result.status}\n`);
        await printArtifactDigests();
      },
    );
  } finally {
    signalShutdown.dispose();
  }
}

process.exitCode =
  signalShutdown.exitCode ?? (result.status === 'passed' ? 0 : 1);

function parseArgs(args) {
  const parsed = {
    platform: undefined,
    artifactsDir: undefined,
    skipBuild: false,
  };
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === '--platform') parsed.platform = args[++index];
    else if (argument === '--artifacts-dir')
      parsed.artifactsDir = args[++index];
    else if (argument === '--skip-build') parsed.skipBuild = true;
    else if (argument === '--help') {
      process.stdout.write(
        'Usage: bun run e2e --platform ios|android [--artifacts-dir <path>] [--skip-build]\n',
      );
      process.exit(0);
    } else throw new Error(`Unknown argument: ${argument}`);
  }
  if (parsed.platform !== 'ios' && parsed.platform !== 'android') {
    throw new Error('--platform must be ios or android');
  }
  return parsed;
}

function assertPrerequisites() {
  if (!existsSync(AGENT_DEVICE)) {
    throw new Error(
      `agent-device is not installed at ${AGENT_DEVICE}; run bun install`,
    );
  }
}

async function revision() {
  const commit = (
    await command('git', ['rev-parse', 'HEAD'], { cwd: REPO_DIR })
  ).stdout.trim();
  const status = (
    await command('git', ['status', '--porcelain=v1'], { cwd: REPO_DIR })
  ).stdout
    .trim()
    .split('\n')
    .filter(Boolean);
  return { commit, dirty: status.length > 0, changes: status };
}

async function toolVersions() {
  const versions = {
    agentDevice: (await command(AGENT_DEVICE, ['--version'])).stdout.trim(),
    bun: (await command('bun', ['--version'])).stdout.trim(),
    node: process.version,
  };
  if (options.platform === 'ios') {
    versions.xcode = (await command('xcodebuild', ['-version'])).stdout.trim();
    versions.ruby = (
      await command(iosToolchain.ruby, ['--version'], {
        env: iosToolchain.environment,
      })
    ).stdout.trim();
    versions.bundler = (
      await command(iosToolchain.bundle, ['--version'], {
        env: iosToolchain.environment,
      })
    ).stdout.trim();
    versions.cocoapods = (
      await command(iosToolchain.bundle, ['exec', 'pod', '--version'], {
        env: iosToolchain.environment,
      })
    ).stdout.trim();
  } else {
    const java = await command(path.join(findJavaHome(), 'bin/java'), [
      '-version',
    ]);
    versions.java = (java.stderr || java.stdout).split('\n')[0];
    versions.androidSdk = androidSdk();
    versions.adb = (
      await command(androidTool('adb'), ['version'])
    ).stdout.split('\n')[0];
    versions.emulator = (
      await command(androidTool('emulator'), ['-version'])
    ).stdout.split('\n')[0];
  }
  return versions;
}

async function bootstrapIosPods() {
  const bundle = findBundler();
  const ruby = findRuby(path.dirname(bundle));
  const environment = {
    PATH: `${path.dirname(bundle)}${path.delimiter}${process.env.PATH ?? ''}`,
    BUNDLE_FROZEN: 'true',
    BUNDLE_PATH: path.join(EXAMPLE_DIR, 'vendor/bundle'),
    RCT_USE_RN_DEP: '0',
    RCT_USE_PREBUILT_RNCORE: '0',
  };
  const bundleCheck = await command(bundle, ['check'], {
    cwd: EXAMPLE_DIR,
    env: environment,
    allowFailure: true,
    capture: true,
    logPath: result.artifacts.podsLog,
  });
  if (bundleCheck.exitCode !== 0) {
    await command(bundle, ['install'], {
      cwd: EXAMPLE_DIR,
      env: environment,
      capture: true,
      logPath: result.artifacts.podsLog,
    });
  }
  await command(
    bundle,
    ['exec', 'pod', 'install', '--project-directory=ios', '--deployment'],
    {
      cwd: EXAMPLE_DIR,
      env: environment,
      capture: true,
      logPath: result.artifacts.podsLog,
    },
  );
  return { bundle, ruby, environment };
}

function findBundler() {
  const candidates = [
    ...(process.env.PATH ?? '')
      .split(path.delimiter)
      .filter(Boolean)
      .map(directory => path.join(directory, 'bundle')),
    '/opt/homebrew/opt/ruby/bin/bundle',
    '/usr/local/opt/ruby/bin/bundle',
    '/usr/local/bin/bundle',
    '/usr/bin/bundle',
  ];
  const bundle = candidates.find(candidate => existsSync(candidate));
  if (!bundle)
    throw new Error(
      'No Bundler executable was found for the iOS pod bootstrap',
    );
  return bundle;
}

function findRuby(bundleDirectory) {
  const candidates = [
    path.join(bundleDirectory, 'ruby'),
    ...(process.env.PATH ?? '')
      .split(path.delimiter)
      .filter(Boolean)
      .map(directory => path.join(directory, 'ruby')),
    '/usr/bin/ruby',
  ];
  const ruby = candidates.find(candidate => existsSync(candidate));
  if (!ruby)
    throw new Error('No Ruby executable was found for the iOS pod bootstrap');
  return ruby;
}

async function createIosSimulator() {
  const inventory = JSON.parse(
    (await command('xcrun', ['simctl', 'list', 'runtimes', '-j'])).stdout,
  );
  const runtime = inventory.runtimes
    .filter(
      item => item.isAvailable && item.identifier.includes('SimRuntime.iOS'),
    )
    .sort((left, right) => compareVersions(right.version, left.version))[0];
  if (!runtime)
    throw new Error('No available iOS simulator runtime is installed');
  const deviceType = runtime.supportedDeviceTypes?.find(
    item => item.productFamily === 'iPhone',
  );
  if (!deviceType)
    throw new Error(`No iPhone device type supports iOS ${runtime.version}`);

  const name = `rnqc-e2e-${runId}`;
  const device = owned.registerDevice({
    id: undefined,
    name,
    platform: 'ios',
    evidence: {
      id: undefined,
      name,
      kind: 'simulator',
      runtime: { id: runtime.identifier, version: runtime.version },
      deviceType: { id: deviceType.identifier, name: deviceType.name },
      owned: true,
    },
  });
  const id = (
    await command('xcrun', [
      'simctl',
      'create',
      name,
      deviceType.identifier,
      runtime.identifier,
    ])
  ).stdout.trim();
  device.id = id;
  device.evidence.id = id;
  await command('xcrun', ['simctl', 'boot', id], { timeoutMs: 60_000 });
  await command('xcrun', ['simctl', 'bootstatus', id, '-b'], {
    timeoutMs: 180_000,
  });
  return device;
}

async function createAndroidEmulator() {
  const image = await selectAndroidImage();
  const javaHome = findJavaHome();
  const avdmanager = androidTool('avdmanager');
  const profiles = (
    await command(avdmanager, ['list', 'device', '-c'], {
      env: androidEnvironment(javaHome),
      allowStderr: true,
    })
  ).stdout
    .split('\n')
    .map(line => line.trim())
    .filter(Boolean);
  const deviceProfile = profiles
    .filter(profile => /^pixel_\d+(?:_pro)?$/.test(profile))
    .sort(compareAndroidProfiles)[0];
  if (!deviceProfile)
    throw new Error('No Android phone hardware profile is installed');

  const name = `rnqc_e2e_${runId.replaceAll('-', '_')}`;
  const port = await availableEmulatorPort();
  const id = `emulator-${port}`;
  const device = owned.registerDevice({
    id,
    name,
    platform: 'android',
    emulator: undefined,
    javaHome,
    evidence: {
      id,
      name,
      kind: 'emulator',
      systemImage: image.packageId,
      apiLevel: image.apiLevel,
      abi: image.abi,
      deviceProfile,
      owned: true,
    },
  });
  await command(
    avdmanager,
    [
      'create',
      'avd',
      '--force',
      '--name',
      name,
      '--package',
      image.packageId,
      '--device',
      deviceProfile,
    ],
    {
      env: androidEnvironment(javaHome),
      input: 'no\n',
      allowStderr: true,
    },
  );

  const log = createWriteStream(result.artifacts.deviceLog, { flags: 'a' });
  const emulator = owned.trackChild(
    spawn(
      androidTool('emulator'),
      [
        '-avd',
        name,
        '-port',
        String(port),
        '-no-snapshot',
        '-no-window',
        '-gpu',
        'swiftshader_indirect',
        '-noaudio',
        '-no-boot-anim',
        '-camera-back',
        'none',
        '-no-metrics',
      ],
      {
        cwd: EXAMPLE_DIR,
        env: { ...process.env, ...androidEnvironment(javaHome) },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    ),
  );
  device.emulator = emulator;
  emulator.stdout.pipe(log);
  emulator.stderr.pipe(log);
  log.once('error', error => {
    emulator.logError = error;
    emulator.kill('SIGTERM');
  });

  await command(androidTool('adb'), ['-s', id, 'wait-for-device'], {
    timeoutMs: 180_000,
    timeoutMessage: `Android emulator ${id} did not connect to adb within 180000ms`,
    watchedChild: emulator,
    watchedChildMessage: `Android emulator ${id} exited before connecting to adb`,
  });
  await waitForAndroidBoot(id, emulator);
  for (const setting of [
    'window_animation_scale',
    'transition_animation_scale',
    'animator_duration_scale',
  ]) {
    await command(androidTool('adb'), [
      '-s',
      id,
      'shell',
      'settings',
      'put',
      'global',
      setting,
      '0',
    ]);
  }
  return device;
}

async function selectAndroidImage() {
  const systemImages = path.join(androidSdk(), 'system-images');
  const candidates = [];
  for (const apiDirectory of await readdir(systemImages, {
    withFileTypes: true,
  })) {
    if (
      !apiDirectory.isDirectory() ||
      !apiDirectory.name.startsWith('android-')
    )
      continue;
    for (const tagDirectory of await readdir(
      path.join(systemImages, apiDirectory.name),
      {
        withFileTypes: true,
      },
    )) {
      if (!tagDirectory.isDirectory()) continue;
      for (const abiDirectory of await readdir(
        path.join(systemImages, apiDirectory.name, tagDirectory.name),
        { withFileTypes: true },
      )) {
        if (!abiDirectory.isDirectory()) continue;
        candidates.push({
          apiLevel: Number(apiDirectory.name.slice('android-'.length)),
          tag: tagDirectory.name,
          abi: abiDirectory.name,
          packageId: `system-images;${apiDirectory.name};${tagDirectory.name};${abiDirectory.name}`,
        });
      }
    }
  }
  const hostAbi = process.arch === 'arm64' ? 'arm64-v8a' : 'x86_64';
  const selected = candidates
    .filter(candidate => candidate.abi === hostAbi)
    .sort((left, right) => right.apiLevel - left.apiLevel)[0];
  if (!selected)
    throw new Error(
      `No installed Android system image matches host ABI ${hostAbi}`,
    );
  return selected;
}

async function buildIos(device) {
  const appPath = path.join(
    EXAMPLE_DIR,
    'ios/build/Build/Products/Debug-iphonesimulator',
    `${APP_NAME}.app`,
  );
  if (!options.skipBuild) {
    await command(
      'xcodebuild',
      [
        '-workspace',
        'ios/QuickCryptoExample.xcworkspace',
        '-scheme',
        APP_NAME,
        '-configuration',
        'Debug',
        '-sdk',
        'iphonesimulator',
        '-destination',
        `platform=iOS Simulator,id=${device.id}`,
        '-derivedDataPath',
        'ios/build',
        'CC=clang',
        'CPLUSPLUS=clang++',
        'LD=clang',
        'LDPLUSPLUS=clang++',
        'ONLY_ACTIVE_ARCH=YES',
        'CODE_SIGNING_ALLOWED=NO',
        'COMPILER_INDEX_STORE_ENABLE=NO',
        'build',
      ],
      { cwd: EXAMPLE_DIR, logPath: result.artifacts.buildLog },
    );
  }
  if (!existsSync(appPath))
    throw new Error(`iOS app was not built at ${appPath}`);
  return { configuration: 'Debug', incremental: true, appPath };
}

async function buildAndroid(device) {
  const appPath = path.join(
    EXAMPLE_DIR,
    'android/app/build/outputs/apk/debug/app-debug.apk',
  );
  const lintReport = path.join(
    REPO_DIR,
    'packages/react-native-quick-crypto/android/build/reports/lint-results-debug.xml',
  );
  if (!options.skipBuild) {
    await command(
      './gradlew',
      [
        ':app:assembleDebug',
        ':react-native-quick-crypto:lintDebug',
        '--no-daemon',
        '--console=plain',
        `-PreactNativeArchitectures=${device.evidence.abi}`,
      ],
      {
        cwd: path.join(EXAMPLE_DIR, 'android'),
        env: androidEnvironment(device.javaHome),
        logPath: result.artifacts.buildLog,
      },
    );
  }
  if (!existsSync(appPath))
    throw new Error(`Android APK was not built at ${appPath}`);
  if (!existsSync(lintReport))
    throw new Error(`Android lint report was not produced at ${lintReport}`);
  await copyFile(lintReport, result.artifacts.lintReport);
  return {
    configuration: 'Debug',
    incremental: true,
    tasks: [':app:assembleDebug', ':react-native-quick-crypto:lintDebug'],
    lintReport: result.artifacts.lintReport,
    appPath,
  };
}

async function startMetro(port) {
  const log = createWriteStream(result.artifacts.metroLog, { flags: 'a' });
  const child = owned.trackChild(
    spawn(
      'bun',
      ['x', 'react-native', 'start', '--client-logs', '--port', String(port)],
      {
        cwd: EXAMPLE_DIR,
        env: process.env,
        detached: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    ),
    { detached: true },
  );
  const metro = owned.registerMetro({ child, port });
  child.stdout.pipe(log);
  child.stderr.pipe(log);
  log.once('error', error => {
    child.logError = error;
    try {
      process.kill(-child.pid, 'SIGTERM');
    } catch {
      child.kill('SIGTERM');
    }
  });
  await waitFor(
    async () => {
      if (child.spawnError) throw child.spawnError;
      if (child.logError) throw child.logError;
      if (childHasExited(child))
        throw new Error(`Metro exited with code ${child.exitCode}`);
      const response = await fetch(`http://127.0.0.1:${port}/status`).catch(
        () => undefined,
      );
      return response?.ok === true;
    },
    60_000,
    'Metro did not become ready',
  );
  await waitFor(
    async () => {
      const response = await fetch(
        `http://127.0.0.1:${port}/index.bundle?platform=${options.platform}&dev=true&minify=false`,
      ).catch(() => undefined);
      if (!response?.ok) return false;
      await response.arrayBuffer();
      return true;
    },
    180_000,
    `${options.platform} Metro bundle did not compile`,
    2_000,
  );
  return metro;
}

async function installApp(device, appPath) {
  await agent(['install', appPath, ...deviceSelector(device)]);
}

async function runSuite(device, metroPort) {
  const selector = deviceSelector(device);
  const launchConsole = path.join(artifactsDir, 'ios-launch-console.log');
  const openArgs = [
    'open',
    APP_ID,
    '--foreground',
    '--relaunch',
    '--metro-port',
    String(metroPort),
    '--session',
    owned.session,
    ...selector,
  ];
  if (device.platform === 'ios')
    openArgs.push('--launch-console', launchConsole);
  await agent(openArgs);
  owned.sessionOpened = true;
  await agent([
    'wait',
    'id="run-all-tests-button"',
    '60000',
    '--session',
    owned.session,
    ...selector,
  ]);
  await agent([
    'press',
    'id="run-all-tests-button"',
    '--settle',
    '--timeout',
    '10000',
    '--session',
    owned.session,
    ...selector,
  ]);
  await agent([
    'wait',
    'id="e2e-completion-summary"',
    '360000',
    '--session',
    owned.session,
    ...selector,
  ]);
  const summaryResponse = await agent([
    'get',
    'text',
    'id="e2e-completion-summary"',
    '--session',
    owned.session,
    ...selector,
  ]);
  await agent([
    'screenshot',
    '--out',
    result.artifacts.screenshot,
    '--session',
    owned.session,
    ...selector,
  ]);
  const text = summaryResponse.data?.text;
  if (typeof text !== 'string')
    throw new Error('agent-device returned no completion summary text');
  const match = RESULT_PATTERN.exec(text);
  if (!match) throw new Error(`Unexpected completion summary: ${text}`);
  return {
    raw: text,
    status: match[1],
    suites: Number(match[2]),
    failedSuites: Number(match[3]),
    tests: Number(match[4]),
    failures: Number(match[5]),
    durationMs: Number(match[6]),
  };
}

async function collectDeviceLog() {
  if (options.platform !== 'android' || !owned.device) return;
  await command(androidTool('adb'), ['-s', owned.device.id, 'logcat', '-d'], {
    allowFailure: true,
    timeoutMs: 10_000,
    logPath: result.artifacts.deviceLog,
  });
}

async function captureFailureScreenshot() {
  if (
    result.status === 'passed' ||
    existsSync(result.artifacts.screenshot) ||
    !owned.device ||
    !owned.sessionOpened
  )
    return;
  await agent([
    'screenshot',
    '--out',
    result.artifacts.screenshot,
    '--session',
    owned.session,
    ...deviceSelector(owned.device),
  ]);
}

async function closeSession() {
  if (!owned.device || !owned.sessionOpened) return;
  await agent([
    'close',
    '--session',
    owned.session,
    ...deviceSelector(owned.device),
  ]);
  owned.sessionOpened = false;
}

async function stopAgentDaemon() {
  if (!owned.agentUsed) return;
  await command(AGENT_DEVICE, ['daemon', 'stop', '--clean', '--json'], {
    cwd: EXAMPLE_DIR,
    env: agentEnvironment(),
  });
}

async function stopMetro() {
  const child = owned.metro?.child;
  if (!child || childHasExited(child)) return;
  try {
    process.kill(-child.pid, 'SIGTERM');
  } catch {
    child.kill('SIGTERM');
  }
  await waitFor(() => childHasExited(child), 5_000, 'Metro did not stop').catch(
    () => {
      try {
        process.kill(-child.pid, 'SIGKILL');
      } catch {
        child.kill('SIGKILL');
      }
    },
  );
}

async function destroyOwnedDevice() {
  const device = owned.device;
  if (!device) return;
  if (device.platform === 'ios') {
    const id = await resolveOwnedIosDeviceId(device);
    if (!id) return;
    await command('xcrun', ['simctl', 'shutdown', id], {
      allowFailure: true,
      timeoutMs: 30_000,
    });
    await command('xcrun', ['simctl', 'delete', id], {
      timeoutMs: 30_000,
    });
    return;
  }
  if (device.emulator) {
    await command(androidTool('adb'), ['-s', device.id, 'emu', 'kill'], {
      allowFailure: true,
      timeoutMs: 10_000,
    });
    await waitFor(
      () => childHasExited(device.emulator),
      10_000,
      'Emulator did not stop',
    ).catch(() => device.emulator.kill('SIGKILL'));
  }
  await command(
    androidTool('avdmanager'),
    ['delete', 'avd', '--name', device.name],
    {
      env: androidEnvironment(device.javaHome),
      allowStderr: true,
      allowFailure: true,
      timeoutMs: 30_000,
    },
  );
  const remainingAvds = (
    await command(androidTool('emulator'), ['-list-avds'], {
      env: androidEnvironment(device.javaHome),
      timeoutMs: 30_000,
    })
  ).stdout
    .split('\n')
    .map(name => name.trim())
    .filter(Boolean);
  if (remainingAvds.includes(device.name))
    throw new Error(`Owned Android AVD was not deleted: ${device.name}`);
}

async function resolveOwnedIosDeviceId(device) {
  if (device.id) return device.id;
  const inventory = JSON.parse(
    (await command('xcrun', ['simctl', 'list', 'devices', '-j'])).stdout,
  );
  const matches = Object.values(inventory.devices)
    .flat()
    .filter(candidate => candidate.name === device.name);
  if (matches.length === 0) return undefined;
  if (matches.length !== 1)
    throw new Error(
      `Refusing to delete ambiguous simulators named ${device.name}`,
    );
  const [match] = matches;
  device.id = match.udid;
  device.evidence.id = match.udid;
  return match.udid;
}

async function agent(args) {
  owned.agentUsed = true;
  const sequence = String(commands.length + 1).padStart(3, '0');
  const response = await command(AGENT_DEVICE, [...args, '--json'], {
    cwd: EXAMPLE_DIR,
    env: agentEnvironment(),
    timeoutMs: 120_000,
    logPath: path.join(
      result.artifacts.agentDevice,
      `${sequence}-${args[0]}.json`,
    ),
    capture: true,
  });
  try {
    return JSON.parse(response.stdout);
  } catch {
    throw new Error(`agent-device ${args[0]} did not return JSON`);
  }
}

function agentEnvironment() {
  const environment = {
    AGENT_DEVICE_STATE_DIR: path.join(artifactsDir, 'agent-device-state'),
    AGENT_DEVICE_DAEMON_IDLE_TIMEOUT_MS: '30000',
  };
  return options.platform === 'android'
    ? { ...environment, ...androidEnvironment(findJavaHome()) }
    : environment;
}

function deviceSelector(device) {
  return device.platform === 'ios'
    ? ['--platform', 'ios', '--udid', device.id]
    : ['--platform', 'android', '--serial', device.id];
}

async function command(executable, args, commandOptions = {}) {
  const started = Date.now();
  const evidence = {
    executable,
    args,
    cwd: commandOptions.cwd ?? EXAMPLE_DIR,
    startedAt: new Date(started).toISOString(),
    exitCode: undefined,
    durationMs: undefined,
  };
  commands.push(evidence);
  const mergedEnv = { ...process.env, ...commandOptions.env };
  const child = owned.trackChild(
    spawn(executable, args, {
      cwd: evidence.cwd,
      env: mergedEnv,
      stdio: ['pipe', 'pipe', 'pipe'],
    }),
  );
  const chunks = { stdout: [], stderr: [] };
  const capture = commandOptions.capture ?? !commandOptions.logPath;
  const log = commandOptions.logPath
    ? createWriteStream(commandOptions.logPath, { flags: 'a' })
    : undefined;
  let logError;
  log?.once('error', error => {
    logError = error;
    child.kill('SIGTERM');
  });
  child.stdout.on('data', chunk => {
    if (capture) chunks.stdout.push(chunk);
    log?.write(chunk);
  });
  child.stderr.on('data', chunk => {
    if (capture) chunks.stderr.push(chunk);
    log?.write(chunk);
  });
  if (commandOptions.input) child.stdin.end(commandOptions.input);
  else child.stdin.end();
  let completion;
  try {
    completion = await waitForChildExit(child, {
      timeoutMs: commandOptions.timeoutMs,
      timeoutMessage: commandOptions.timeoutMessage,
      watchedChild: commandOptions.watchedChild,
      watchedChildMessage: commandOptions.watchedChildMessage,
    });
  } catch (error) {
    log?.end();
    evidence.exitCode = error.exitCode;
    if (error.signal) evidence.signal = error.signal;
    evidence.durationMs = Date.now() - started;
    throw error;
  }
  const { exitCode, signal } = completion;
  log?.end();
  const stdout = Buffer.concat(chunks.stdout).toString('utf8');
  const stderr = Buffer.concat(chunks.stderr).toString('utf8');
  evidence.exitCode = exitCode;
  if (signal) evidence.signal = signal;
  evidence.durationMs = Date.now() - started;
  if (logError) throw logError;
  signalShutdown.throwIfRequested();
  if (exitCode !== 0 && !commandOptions.allowFailure) {
    const error = new Error(
      `${executable} ${args.join(' ')} exited ${exitCode ?? signal}: ${stderr.trim() || stdout.trim()}`,
    );
    error.exitCode = exitCode;
    error.signal = signal;
    throw error;
  }
  if (stderr && !commandOptions.allowStderr && exitCode === 0)
    evidence.stderr = stderr.trim();
  return { stdout, stderr, exitCode };
}

async function waitFor(check, timeoutMs, message, intervalMs = 1_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    signalShutdown.throwIfRequested();
    if (await check()) return;
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }
  throw new Error(message);
}

async function waitForAndroidBoot(serial, emulator) {
  await waitFor(
    async () => {
      if (emulator.logError) throw emulator.logError;
      if (emulator.spawnError) throw emulator.spawnError;
      if (childHasExited(emulator))
        throw new Error(`Android emulator exited ${emulator.exitCode}`);
      const state = await command(
        androidTool('adb'),
        ['-s', serial, 'shell', 'getprop', 'sys.boot_completed'],
        {
          allowFailure: true,
          timeoutMs: 10_000,
        },
      );
      return state.stdout.trim() === '1';
    },
    180_000,
    `Android emulator ${serial} did not finish booting`,
    2_000,
  );
}

function compareVersions(left, right) {
  return left.localeCompare(right, undefined, { numeric: true });
}

function childHasExited(child) {
  return child.exitCode !== null || child.signalCode !== null;
}

function compareAndroidProfiles(left, right) {
  const version = profileVersion(right) - profileVersion(left);
  if (version !== 0) return version;
  return right.localeCompare(left);
}

function profileVersion(profile) {
  return Number(/pixel_(\d+)/.exec(profile)?.[1] ?? 0);
}

async function availablePort() {
  return await new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
  });
}

async function availableEmulatorPort() {
  for (let port = 5554; port <= 5680; port += 2) {
    if ((await portIsFree(port)) && (await portIsFree(port + 1))) return port;
  }
  throw new Error('No free Android emulator console port was found');
}

async function portIsFree(port) {
  return await new Promise(resolve => {
    const server = createServer();
    server.once('error', () => resolve(false));
    server.listen(port, '127.0.0.1', () => server.close(() => resolve(true)));
  });
}

function androidSdk() {
  const candidates = [
    process.env.ANDROID_HOME,
    process.env.ANDROID_SDK_ROOT,
    path.join(homedir(), 'Library/Android/sdk'),
    path.join(homedir(), 'Android/Sdk'),
    path.join(homedir(), 'android-sdk'),
    '/opt/android-sdk',
    '/usr/local/lib/android/sdk',
    '/usr/lib/android-sdk',
  ].filter(Boolean);
  const sdk = candidates.find(
    candidate =>
      existsSync(path.join(candidate, 'platform-tools/adb')) &&
      existsSync(path.join(candidate, 'emulator/emulator')),
  );
  if (!sdk)
    throw new Error(
      'No Android SDK with platform-tools and emulator was found',
    );
  return sdk;
}

function androidTool(name) {
  if (name === 'emulator') return path.join(androidSdk(), 'emulator/emulator');
  if (name === 'adb') return path.join(androidSdk(), 'platform-tools/adb');
  return path.join(androidSdk(), 'cmdline-tools/latest/bin', name);
}

function androidEnvironment(javaHome) {
  const sdk = androidSdk();
  return { JAVA_HOME: javaHome, ANDROID_HOME: sdk, ANDROID_SDK_ROOT: sdk };
}

function findJavaHome() {
  const candidates = [
    process.env.JAVA_HOME,
    '/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home',
    '/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home',
    '/usr/local/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home',
    '/usr/local/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home',
    ...javaHomesUnder('/usr/lib/jvm'),
    ...javaHomesUnder(path.join(homedir(), '.sdkman/candidates/java')),
    path.join(homedir(), 'android-studio/jbr'),
    '/opt/android-studio/jbr',
    '/usr/local/android-studio/jbr',
    '/Applications/Android Studio.app/Contents/jbr/Contents/Home',
  ].filter(Boolean);
  const javaHome = candidates.find(candidate => {
    if (!existsSync(path.join(candidate, 'bin/java'))) return false;
    const major = javaMajorVersion(candidate);
    return major === 17 || major === 21;
  });
  if (!javaHome)
    throw new Error(
      'No Gradle-compatible JDK 17 or 21 was found for Android builds and avdmanager',
    );
  return javaHome;
}

function javaHomesUnder(directory) {
  if (!existsSync(directory)) return [];
  return readdirSync(directory, { withFileTypes: true })
    .filter(entry => entry.isDirectory() || entry.isSymbolicLink())
    .map(entry => path.join(directory, entry.name));
}

function javaMajorVersion(javaHome) {
  try {
    const release = readFileSync(path.join(javaHome, 'release'), 'utf8');
    return Number(/JAVA_VERSION="(?:1\.)?(\d+)/.exec(release)?.[1]);
  } catch {
    return undefined;
  }
}

function serializeError(error) {
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      ...(error.exitCode === undefined ? {} : { exitCode: error.exitCode }),
      ...(error.signal === undefined ? {} : { signal: error.signal }),
      stack: error.stack,
    };
  }
  return { name: 'Error', message: String(error) };
}

function recordCleanupError(error) {
  result.cleanupErrors ??= [];
  result.cleanupErrors.push(serializeError(error));
  result.status = 'infrastructure_failure';
  result.error ??= {
    name: 'CleanupError',
    message: 'One or more owned E2E resources could not be cleaned up',
  };
}

async function printArtifactDigests() {
  for (const artifact of [
    result.artifacts.result,
    result.artifacts.screenshot,
  ]) {
    if (!existsSync(artifact)) {
      process.stdout.write(`ARTIFACT_SHA256 missing path=${artifact}\n`);
      continue;
    }
    const digest = createHash('sha256')
      .update(await readFile(artifact))
      .digest('hex');
    process.stdout.write(`ARTIFACT_SHA256 sha256=${digest} path=${artifact}\n`);
  }
}
