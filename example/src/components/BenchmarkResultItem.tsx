import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import type { BenchmarkResult } from '../types/results';
// import { calculateTimes, formatNumber } from '../benchmarks/utils';
// import { colors } from '../styles/colors';

type BenchmarkResultItemProps = {
  benchmarkResult: BenchmarkResult;
};

export const BenchmarkResultItemHeader: React.FC = () => {
  return (
    <View style={styles.itemContainer}>
      <Text style={styles.text}>&nbsp;</Text>
      <Text style={[styles.text, styles.description]}>&nbsp;</Text>
      <Text style={styles.label}>times</Text>
      <Text style={styles.label}>rnqc</Text>
      <Text style={styles.label}>challenger</Text>
    </View>
  );
};

export const BenchmarkResultItem: React.FC<BenchmarkResultItemProps> = ({
  benchmarkResult,
}: BenchmarkResultItemProps) => {
  console.log(benchmarkResult);
  return (null);
  // const emoji = result.type === 'faster' ? '🐇' : '🐢';
  // const times = calculateTimes(result);
  // const timesType = result.type === 'faster' ? 'faster' : 'slower';
  // const timesStyle = timesType === 'faster' ? styles.faster : styles.slower;

  // return (
  //   <View style={styles.itemContainer}>
  //     <Text style={styles.text}>{emoji}</Text>
  //     <Text style={[styles.text, styles.description]}>
  //       {result.challenger || result.libName}
  //     </Text>
  //     <Text style={[styles.value, timesStyle]}>
  //       {formatNumber(times, 2, 'x')}
  //     </Text>
  //     <Text style={styles.value}>{formatNumber(result.us, 2, 'ms')}</Text>
  //     <Text style={styles.value}>{formatNumber(result.them, 2, 'ms')}</Text>
  //   </View>
  // );
};

const styles = StyleSheet.create({
  itemContainer: {
    flexDirection: 'row',
    padding: 5,
  },
  text: {
    flexShrink: 1,
    paddingRight: 5,
    fontSize: 12,
  },
  description: {
    flex: 3,
  },
  // value: {
  //   fontSize: 10,
  //   fontFamily: 'Courier New',
  //   minWidth: 60,
  //   textAlign: 'center',
  //   alignSelf: 'flex-end',
  // },
  label: {
    fontSize: 8,
    fontWeight: 'bold',
    minWidth: 60,
    textAlign: 'center',
  },
  // faster: {
  //   color: colors.green,
  //   fontWeight: 'bold',
  // },
  // slower: {
  //   color: colors.red,
  //   fontWeight: 'bold',
  // },
});
