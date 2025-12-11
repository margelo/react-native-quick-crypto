// Shared test data for benchmarks
// Generate test data of different sizes using repeating pattern
const generateString = (sizeInMB: number): string => {
  const chunk =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytesPerMB = 1024 * 1024;
  const totalBytes = Math.floor(sizeInMB * bytesPerMB);
  const repeatCount = Math.ceil(totalBytes / chunk.length);
  return chunk.repeat(repeatCount).substring(0, totalBytes);
};

// Pre-generate test data once for all benchmarks
export const text100KB = generateString(0.1);
export const text1MB = generateString(1);
export const text8MB = generateString(8);

// Pre-generate Buffer versions for comparison
export const buffer100KB = Buffer.from(text100KB);
export const buffer1MB = Buffer.from(text1MB);
export const buffer8MB = Buffer.from(text8MB);
