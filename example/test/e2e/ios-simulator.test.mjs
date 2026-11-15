import assert from 'node:assert/strict';
import test from 'node:test';

import { selectIosSimulator } from './ios-simulator.mjs';

const duoRuntime = {
  identifier: 'com.apple.CoreSimulator.SimRuntime.iOS-27-2-iPhone19-4',
  version: '27.2',
  isAvailable: true,
  supportedDeviceTypes: [
    {
      identifier: 'com.apple.CoreSimulator.SimDeviceType.iPhone-Duo',
      name: 'iPhone Duo',
      productFamily: 'iPhone',
    },
  ],
};

const genericRuntime = {
  identifier: 'com.apple.CoreSimulator.SimRuntime.iOS-27-2',
  version: '27.2',
  isAvailable: true,
  supportedDeviceTypes: [
    {
      identifier: 'com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro',
      name: 'iPhone 18 Pro',
      productFamily: 'iPhone',
    },
  ],
};

test('prefers a single-display iPhone when a Duo-only runtime shares the newest version', () => {
  const selected = selectIosSimulator([duoRuntime, genericRuntime]);
  assert.equal(selected.runtime.identifier, genericRuntime.identifier);
  assert.equal(selected.deviceType.name, 'iPhone 18 Pro');
});

test('keeps a newer single-display runtime ahead of an older one', () => {
  const older = {
    ...genericRuntime,
    identifier: 'com.apple.CoreSimulator.SimRuntime.iOS-26-2',
    version: '26.2',
  };
  const selected = selectIosSimulator([older, genericRuntime]);
  assert.equal(selected.runtime.version, '27.2');
});

test('rejects a runtime list that only offers iPhone Duo', () => {
  assert.throws(
    () => selectIosSimulator([duoRuntime]),
    /No single-display iPhone simulator runtime is installed/,
  );
});
