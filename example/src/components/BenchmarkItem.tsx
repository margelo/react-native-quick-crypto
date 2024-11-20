import React, { useEffect, useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ActivityIndicator,
  InteractionManager,
} from 'react-native';
import BouncyCheckbox from 'react-native-bouncy-checkbox';
import { useNavigation } from '@react-navigation/native';
// import { calculateTimes, formatNumber } from '../benchmarks/utils';
import { colors } from '../styles/colors';
import type { BenchmarkSuite } from '../benchmarks/benchmarks';
import { calculateTimes, formatNumber } from '../benchmarks/utils';

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

  // suite runs
  useEffect(() => {
    setRunning(suite.state === 'running');
  }, [suite.state]);

  useEffect(() => {
    const run = async () => {
      await waitForGc();
      suite.run(multiplier);
      suite.state = 'done';
      setRunning(false);
    };
    if (running) run();
  }, [running]);

  function delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async function waitForGc(): Promise<void> {
    await delay(500);
    return new Promise(resolve => {
      requestAnimationFrame(() => {
        InteractionManager.runAfterInteractions(() => {
          resolve();
        });
      });
    });
  }

  // results handling
  const usTime = suite.results.reduce((acc, result) => {
    return acc + result.us;
  }, 0);
  const themTime = suite.results.reduce((acc, result) => {
    return acc + result.time;
  }, 0);
  const times = calculateTimes(usTime, themTime);
  const timesStyle = usTime < themTime ? styles.faster : styles.slower;

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
