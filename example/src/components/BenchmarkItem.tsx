import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity, ActivityIndicator } from 'react-native';
import BouncyCheckbox from 'react-native-bouncy-checkbox';
import type { BenchmarkResult } from '../types/results';
import { useNavigation } from '@react-navigation/native';
// import { calculateTimes, formatNumber } from '../benchmarks/utils';
import { colors } from '../styles/colors';

type BenchmarkItemProps = {
  description: string;
  value: boolean;
  count: number;
  results: BenchmarkResult[];
  running: boolean;
  onToggle: (description: string) => void;
};

export const BenchmarkItem: React.FC<BenchmarkItemProps> = ({
  description,
  value,
  count,
  results,
  running,
  onToggle,
}: BenchmarkItemProps) => {
  // console.log('BenchmarkItem', description, running);
  const navigation = useNavigation();

  return (
    <View style={styles.container}>
      {running ? (
        <View style={styles.checkbox}>
          <ActivityIndicator size="small" color={colors.white} />
        </View>
      ) : (
        <BouncyCheckbox
          isChecked={value}
          onPress={() => {
            onToggle(description);
          }}
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
            results,
            suiteName: description,
          });
        }}>
        <Text style={styles.label} numberOfLines={1}>
          {description} {running ? '(running)' : '(not running)'}
        </Text>
        {/* <Text style={[styles.times, timesStyle]} numberOfLines={1}>
          {formatNumber(times, 2, 'x')}
        </Text> */}
        <Text style={styles.count} numberOfLines={1}>
          {count}
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
