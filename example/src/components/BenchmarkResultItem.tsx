import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import type { BenchmarkResult } from '../types/benchmarks';
import { calculateTimes, formatNumber } from '../benchmarks/utils';
import { colors } from '../styles/colors';

type BenchmarkResultItemProps = {
  result: BenchmarkResult;
};

type Key = 'throughput' | 'latency';

export const BenchmarkResultItemHeader: React.FC = () => {
  return (
    <View style={styles.itemContainer}>
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
  // Check if benchmark errored out
  const usHasError = result.us?.error !== undefined;
  const themHasError = result.them?.error !== undefined;

  if (usHasError || themHasError) {
    return (
      <View>
        <View style={styles.subContainer}>
          <Text style={[styles.sub, styles.benchName]}>{result.benchName}</Text>
        </View>
        <View style={styles.subContainer}>
          <Text style={[styles.sub, styles.subLabel]}>error</Text>
          <Text style={[styles.sub, styles.subValue, styles.slower]}>
            {usHasError ? 'rnqc failed' : ''}
            {usHasError && themHasError ? ' / ' : ''}
            {themHasError ? `${result.challenger} failed` : ''}
          </Text>
        </View>
      </View>
    );
  }

  const hasComparison = result.them !== undefined;

  const rows = ['throughput', 'latency'].map((key, i) => {
    const us = result.us![key as Key].mean;
    const them = hasComparison ? result.them![key as Key].mean : 0;
    const comparison = key === 'throughput' ? us > them : us < them;
    const places = key === 'throughput' ? 2 : 3;
    const times = hasComparison ? calculateTimes(us, them) : 0;
    const emoji = comparison ? '🐇' : '🐢';
    const timesType = comparison ? 'faster' : 'slower';
    const timesStyle = timesType === 'faster' ? styles.faster : styles.slower;

    return (
      <View key={i}>
        <View style={styles.itemContainer}>
          <Text style={styles.text}>{emoji}</Text>
          <Text style={[styles.text, styles.description]}>
            {key} {key === 'throughput' ? '(ops/s)' : '(ms)'}
          </Text>
          {hasComparison && (
            <Text style={[styles.value, timesStyle]}>
              {formatNumber(times, 2, 'x')}
            </Text>
          )}
          <Text style={styles.value}>{formatNumber(us, places, '')}</Text>
          {hasComparison && (
            <Text style={styles.value}>{formatNumber(them, places, '')}</Text>
          )}
        </View>
      </View>
    );
  });

  return (
    <View>
      <View style={styles.subContainer}>
        <Text style={[styles.sub, styles.benchName]}>{result.benchName}</Text>
      </View>
      {rows}
      <View style={styles.subContainer}>
        <Text style={[styles.sub, styles.subLabel]}>challenger</Text>
        <Text style={[styles.sub, styles.subValue]}>{result.challenger}</Text>
      </View>
      {result.notes !== '' && (
        <View style={styles.subContainer}>
          <Text style={[styles.sub, styles.subLabel]}>notes</Text>
          <Text style={[styles.sub, styles.subValue]}>{result.notes}</Text>
        </View>
      )}
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
    paddingTop: 8,
  },
  text: {
    flexShrink: 1,
    paddingRight: 5,
    fontSize: 12,
  },
  description: {
    flex: 3,
    fontSize: 10,
    alignSelf: 'flex-end',
  },
  value: {
    fontSize: 10,
    fontFamily: 'Courier New',
    minWidth: 60,
    textAlign: 'right',
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
  benchName: {
    fontSize: 10,
    fontWeight: 'bold',
    flex: 1,
    textAlign: 'left',
  },
});
