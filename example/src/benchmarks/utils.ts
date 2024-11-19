export const formatNumber = (
  n: number,
  decimals: number,
  suffix: string,
): string => {
  if (isNaN(n)) {
    return '';
  }
  return n.toFixed(decimals) + suffix;
};

export const calculateTimes = (typ: 'faster' | 'slower', us: number, them: number): number => {
  return typ === 'faster'
    ? 1 + (them - us) / us
    : 1 + (us - them) / them;
};
