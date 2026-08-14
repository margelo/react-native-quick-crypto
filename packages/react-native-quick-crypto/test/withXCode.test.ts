import { execFileSync } from 'child_process';
import { needsRaising, patchPodfile } from '../src/expo-plugin/withXCode';

const PODFILE = `require File.join(File.dirname(\`node --print "require.resolve('expo/package.json')"\`), "scripts/autolinking")

platform :ios, podfile_properties['ios.deploymentTarget'] || '15.1'

target 'example' do
  use_expo_modules!

  post_install do |installer|
    react_native_post_install(installer, config[:reactNativePath])
  end
end
`;

test('needsRaising floors anything below the minimum', () => {
  expect(needsRaising(undefined)).toBe(true);
  expect(needsRaising('')).toBe(true);
  expect(needsRaising('15.1')).toBe(true);
  expect(needsRaising('9.0')).toBe(true);
});

test('needsRaising leaves the minimum and anything above it alone', () => {
  expect(needsRaising('16.4')).toBe(false);
  expect(needsRaising('17.0')).toBe(false);
  expect(needsRaising('26.0')).toBe(false);
});

test('needsRaising compares component-wise, not lexically or as a float', () => {
  expect(needsRaising('16.10')).toBe(false);
  expect(needsRaising('16.4.1')).toBe(false);
  expect(needsRaising('16.3.9')).toBe(true);
});

test('needsRaising leaves an unparseable target alone', () => {
  const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
  expect(needsRaising('17.0-beta')).toBe(false);
  expect(warn).toHaveBeenCalled();
  warn.mockRestore();
});

test('patchPodfile injects the floor into post_install', () => {
  const patched = patchPodfile(PODFILE);
  expect(patched).toMatch(/Gem::Version\.new\('16\.4'\)/);
  expect(patched).toMatch(/react_native_post_install/);
});

test('patchPodfile leaves a Podfile that already pins a target alone', () => {
  const pinned = PODFILE.replace(
    'react_native_post_install(installer, config[:reactNativePath])',
    "config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = '17.0'",
  );
  expect(patchPodfile(pinned)).toBe(pinned);
});

test('patchPodfile warns instead of silently no-oping when post_install is missing', () => {
  const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
  const noPostInstall = "platform :ios, '15.1'\n";
  expect(patchPodfile(noPostInstall)).toBe(noPostInstall);
  expect(warn).toHaveBeenCalled();
  warn.mockRestore();
});

// The injected block is Ruby generated from a template string - nothing else in
// the toolchain parses it, so check it against a real interpreter when present.
const ruby = (() => {
  try {
    execFileSync('ruby', ['-e', '']);
    return test;
  } catch {
    return test.skip;
  }
})();

ruby('the injected Ruby is syntactically valid', () => {
  execFileSync('ruby', ['-c', '-'], { input: patchPodfile(PODFILE) });
});

ruby('the injected Ruby raises low targets and preserves high ones', () => {
  const block = patchPodfile(PODFILE)
    .split('installer.pods_project.targets.each do |target|')[1]
    ?.split('\n      end\n    end')[0]
    ?.split('target.build_configurations.each do |config|')[1];

  const result = execFileSync(
    'ruby',
    [
      '-e',
      `
      require 'json'
      settings = JSON.parse(ARGV[0])
      puts(settings.map { |s|
        config = Struct.new(:build_settings).new(s)
        ${block}
        config.build_settings['IPHONEOS_DEPLOYMENT_TARGET']
      }.to_json)
      `,
      JSON.stringify([
        { IPHONEOS_DEPLOYMENT_TARGET: '15.1' },
        { IPHONEOS_DEPLOYMENT_TARGET: '16.10' },
        { IPHONEOS_DEPLOYMENT_TARGET: '17.0.1' },
        { IPHONEOS_DEPLOYMENT_TARGET: 'garbage' },
        {},
      ]),
    ],
    { encoding: 'utf-8' },
  );

  expect(JSON.parse(result)).toEqual([
    '16.4', // raised
    '16.10', // preserved - float compare would have downgraded this
    '17.0.1', // preserved - unquoted interpolation would have been a syntax error
    '16.4', // unparseable, floored
    '16.4', // absent, floored
  ]);
});
