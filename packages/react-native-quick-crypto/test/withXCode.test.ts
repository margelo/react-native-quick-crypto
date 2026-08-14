import { resolveDeploymentTarget } from '../src/expo-plugin/withXCode';

test('resolveDeploymentTarget keeps a higher app target', () => {
  const target = resolveDeploymentTarget([
    ['expo-build-properties', { ios: { deploymentTarget: '17.0' } }],
  ]);
  expect(target).toBe('17.0');
});

test('resolveDeploymentTarget raises a lower or missing app target', () => {
  expect(
    resolveDeploymentTarget([
      ['expo-build-properties', { ios: { deploymentTarget: '15.1' } }],
    ]),
  ).toBe('16.4');
  expect(resolveDeploymentTarget([['expo-build-properties', {}]])).toBe('16.4');
  expect(resolveDeploymentTarget(['some-other-plugin'])).toBe('16.4');
  expect(resolveDeploymentTarget(undefined)).toBe('16.4');
});

test('resolveDeploymentTarget compares numerically, not lexically', () => {
  expect(
    resolveDeploymentTarget([
      ['expo-build-properties', { ios: { deploymentTarget: '16.10' } }],
    ]),
  ).toBe('16.10');
  expect(
    resolveDeploymentTarget([
      ['expo-build-properties', { ios: { deploymentTarget: '9.0' } }],
    ]),
  ).toBe('16.4');
});
