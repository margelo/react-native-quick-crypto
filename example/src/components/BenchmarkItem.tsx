import React, { useEffect, useState } from 'react';
import { View, Text, StyleSheet, TouchableOpacity, ActivityIndicator } from 'react-native';
import BouncyCheckbox from 'react-native-bouncy-checkbox';
import { useNavigation } from '@react-navigation/native';
// import { calculateTimes, formatNumber } from '../benchmarks/utils';
import { colors } from '../styles/colors';
import type { BenchmarkSuite } from '../benchmarks/benchmarks';

type BenchmarkItemProps = {
  suite: BenchmarkSuite;
  toggle: () => void;
  multiplier: number;
};

export const BenchmarkItem: React.FC<BenchmarkItemProps> = ({
  suite,
  toggle,
  multiplier,
}: BenchmarkItemProps) => {
  const [running, setRunning] = useState(false);
  const navigation = useNavigation();

  useEffect(() => {
    setRunning(suite.state === 'running');
  }, [suite.state]);

  useEffect(() => {
    if (running) {
      suite.run(multiplier);
      suite.state = 'done';
      setRunning(false);
    }
  }, [running]);

  return (
    <View style={styles.container}>
      {running ? (
        <View style={styles.spinner}>
          <ActivityIndicator size="small" color={colors.blue} />
        </View>
      ) : (
        <BouncyCheckbox
          isChecked={suite.enabled}
          onPress={() => toggle()}
          disableText={true}
          fillColor={colors.blue}
          style={styles.checkbox}
        />
      )}
      <TouchableOpacity
        style={styles.touchable}
        onPress={() => {
          // @ts-expect-error - not dealing with navigation types rn
          navigation.navigate('BenchmarkDetailsScreen', {
            results: suite.results,
            suiteName: suite.name,
          });
        }}>
        <Text style={styles.label} numberOfLines={1}>
          {suite.name}
        </Text>
        {/* <Text style={[styles.times, timesStyle]} numberOfLines={1}>
          {formatNumber(times, 2, 'x')}
        </Text> */}
        <Text style={styles.count} numberOfLines={1}>
          {suite.benchmarks.length}
        </Text>
      </TouchableOpacity>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    width: '100%',
    flexDirection: 'row',
    alignContent: 'center',
    alignItems: 'center',
    justifyContent: 'space-evenly',
    gap: 10,
    borderBottomWidth: 1,
    borderBottomColor: colors.gray,
    paddingHorizontal: 10,
  },
  checkbox: {
    transform: [{ scaleX: 0.7 }, { scaleY: 0.7 }],
  },
  spinner: {
    padding: 2.5,
    transform: [{ scaleX: 0.8 }, { scaleY: 0.8 }],
  },
  label: {
    fontSize: 12,
    flex: 8,
  },
  touchable: {
    flex: 1,
    flexDirection: 'row',
  },
  // faster: {
  //   color: colors.green,
  // },
  // slower: {
  //   color: colors.red,
  // },
  // times: {
  //   fontSize: 12,
  //   fontWeight: 'bold',
  //   flex: 1,
  //   textAlign: 'right',
  // },
  count: {
    fontSize: 12,
    fontWeight: 'bold',
    flex: 1,
    textAlign: 'right',
  },
});
