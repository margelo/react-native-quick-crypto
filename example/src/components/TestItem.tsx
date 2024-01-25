import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import Checkbox from '@react-native-community/checkbox';
import type { TestResult } from '../types/TestResults';

type TestItemProps = {
  description: string;
  value: boolean;
  count: number;
  results: TestResult[];
  onToggle: (description: string) => void;
};

export const TestItem: React.FC<TestItemProps> = ({
  description,
  value,
  count,
  results,
  onToggle,
}: TestItemProps) => {
  // get pass/fail stats from results
  let pass = 0;
  let fail = 0;
  results.map((r) => {
    if (r.type === 'correct') pass++;
    if (r.type === 'incorrect') fail++;
  });

  return (
    <View style={styles.container}>
      <Checkbox
        value={value}
        onValueChange={() => {
          onToggle(description);
        }}
      />
      <Text style={styles.label} numberOfLines={1}>
        {description}
      </Text>
      <Text style={[styles.pass, styles.count]} numberOfLines={1}>
        {pass || ''}
      </Text>
      <Text style={[styles.fail, styles.count]} numberOfLines={1}>
        {fail || ''}
      </Text>
      <Text style={styles.count} numberOfLines={1}>
        {count}
      </Text>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    width: '100%',
    padding: 10,
    flexDirection: 'row',
    alignContent: 'center',
    alignItems: 'center',
    justifyContent: 'space-evenly',
    gap: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#ccc',
  },
  label: {
    fontSize: 12,
    flex: 8,
  },
  pass: {
    color: 'green',
  },
  fail: {
    color: 'red',
  },
  count: {
    fontSize: 12,
    flex: 1,
    textAlign: 'right',
  },
});
