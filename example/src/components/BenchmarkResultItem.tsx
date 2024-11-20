import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import type { BenchmarkResult } from '../types/benchmarks';
import { formatNumber } from '../benchmarks/utils';
import { colors } from '../styles/colors';

type BenchmarkResultItemProps = {
  result: BenchmarkResult;
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
  result,
}: BenchmarkResultItemProps) => {
  const emoji = result.type === 'faster' ? '🐇' : '🐢';
  const timesType = result.type === 'faster' ? 'faster' : 'slower';
  const timesStyle = timesType === 'faster' ? styles.faster : styles.slower;

  return (
    <View>
      <View style={styles.itemContainer}>
        <Text style={styles.text}>{emoji}</Text>
        <Text style={[styles.text, styles.description]}>{result.fnName}</Text>
        <Text style={[styles.value, timesStyle]}>
          {formatNumber(result.times, 2, 'x')}
        </Text>
        <Text style={styles.value}>{formatNumber(result.us, 2, 'ms')}</Text>
        <Text style={styles.value}>{formatNumber(result.time, 2, 'ms')}</Text>
      </View>
      <View style={styles.subContainer}>
        <Text style={[styles.sub, styles.subLabel]}>challenger</Text>
        <Text style={[styles.sub, styles.subValue]}>{result.challenger}</Text>
        <Text style={[styles.sub, styles.subLabel]}>runs</Text>
        <Text style={[styles.sub, styles.subValue]}>{result.runCount}</Text>
      </View>
      <View style={styles.subContainer}>
        <Text style={[styles.sub, styles.subLabel]}>notes</Text>
        <Text style={[styles.sub, styles.notes]}>{result.notes}</Text>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  itemContainer: {
    flexDirection: 'row',
    padding: 4,
  },
  subContainer: {
    flexDirection: 'row',
    paddingHorizontal: 4,
  },
  text: {
    flexShrink: 1,
    paddingRight: 5,
    fontSize: 12,
  },
  description: {
    flex: 3,
  },
  value: {
    fontSize: 10,
    fontFamily: 'Courier New',
    minWidth: 60,
    textAlign: 'center',
    alignSelf: 'flex-end',
  },
  label: {
    fontSize: 8,
    fontWeight: 'bold',
    minWidth: 60,
    textAlign: 'center',
  },
  faster: {
    color: colors.green,
    fontWeight: 'bold',
  },
  slower: {
    color: colors.red,
    fontWeight: 'bold',
  },
  sub: {
    fontSize: 8,
  },
  subLabel: {
    flex: 1,
    fontWeight: 'bold',
    marginRight: 5,
  },
  subValue: {
    flex: 2,
  },
  notes: {
    paddingTop: 2,
    flex: 5,
  },
});
