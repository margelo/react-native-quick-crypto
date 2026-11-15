// A device-specific runtime such as iOS-27-2-iPhone19-4 can sort ahead of the
// generic runtime at the same version and offer only iPhone Duo. simctl
// screenshot refuses that device until a display is named, so the runner
// keeps the newest runtime that has a single-display iPhone.

export function selectIosSimulator(runtimes) {
  const available = runtimes
    .filter(
      item =>
        item.isAvailable &&
        String(item.identifier ?? '').includes('SimRuntime.iOS'),
    )
    .sort((left, right) => compareVersions(right.version, left.version));
  for (const runtime of available) {
    const deviceType = runtime.supportedDeviceTypes?.find(
      isSingleDisplayIphone,
    );
    if (deviceType) return { runtime, deviceType };
  }
  if (available.length === 0)
    throw new Error('No available iOS simulator runtime is installed');
  throw new Error('No single-display iPhone simulator runtime is installed');
}

function isSingleDisplayIphone(item) {
  return item.productFamily === 'iPhone' && !isIphoneDuo(item);
}

function isIphoneDuo(item) {
  return (
    String(item.identifier ?? '').includes('iPhone-Duo') ||
    /^iPhone Duo\b/.test(item.name ?? '')
  );
}

function compareVersions(left, right) {
  return String(left).localeCompare(String(right), undefined, {
    numeric: true,
  });
}
