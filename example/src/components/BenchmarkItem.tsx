import React, { useEffect, useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ActivityIndicator,
} from 'react-native';
import BouncyCheckbox from 'react-native-bouncy-checkbox';
import { useNavigation } from '@react-navigation/native';
import { colors } from '../styles/colors';
import type { BenchmarkSuite } from '../benchmarks/benchmarks';
import { calculateTimes, formatNumber } from '../benchmarks/utils';

type BenchmarkItemProps = {
  suite: BenchmarkSuite;
  toggle: () => void;
  bumpRunCurrent: () => void;
};

export const BenchmarkItem: React.FC<BenchmarkItemProps> = ({
  suite,
  toggle,
  bumpRunCurrent,
}: BenchmarkItemProps) => {
  const [running, setRunning] = useState(false);
  const navigation = useNavigation();

  // suite runs
  useEffect(() => {
    setRunning(suite.state === 'running');
  }, [suite.state]);

  useEffect(() => {
    const run = async () => {
      await suite.run();
      setRunning(false);
      bumpRunCurrent();
    };
    if (running) {
      run();
    }
  }, [running]);

  // results handling
  const usTput = suite.results.reduce((acc, result) => {
    return acc + (result.us?.throughput.mean || 0);
  }, 0);
  const themTput = suite.results.reduce((acc, result) => {
    return acc + (result.them?.throughput.mean || 0);
  }, 0);
  const times = calculateTimes(usTput, themTput);
  const timesStyle = usTput > themTput ? styles.faster : styles.slower;

  // render component
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
            name: suite.name,
          });
        }}>
        <Text style={styles.label} numberOfLines={1}>
          {suite.name}
        </Text>
        <Text style={[styles.times, timesStyle]} numberOfLines={1}>
          {formatNumber(times, 2, 'x')}
        </Text>
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
    flex: 3,
  },
  touchable: {
    flex: 1,
    flexDirection: 'row',
  },
  faster: {
    color: colors.green,
  },
  slower: {
    color: colors.red,
  },
  times: {
    fontSize: 12,
    fontWeight: 'bold',
    flex: 1,
    textAlign: 'right',
  },
  count: {
    fontSize: 12,
    fontWeight: 'bold',
    flex: 1,
    textAlign: 'right',
  },
});
