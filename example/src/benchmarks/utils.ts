import type { BenchmarkResult } from '../types/Results'

export const formatNumber = (
  n: number,
  decimals: number,
  suffix: string
): string => {
  if (isNaN(n)) {
    return ''
  }
  return n.toFixed(decimals) + suffix
}

export const calculateTimes = (result: BenchmarkResult): number => {
  return result.type === 'faster'
    ? 1 + (result.them - result.us) / result.us
    : 1 + (result.us - result.them) / result.them
}
