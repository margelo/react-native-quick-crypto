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

export const calculateTimes = (us: number, them: number): number => {
  return us < them
    ? 1 + (them - us) / us
    : 1 + (us - them) / them;
};
