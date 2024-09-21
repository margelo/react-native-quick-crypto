import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import BouncyCheckbox from 'react-native-bouncy-checkbox';
import type { TestResult } from '../types/Results';
import { useNavigation } from '@react-navigation/native';
import { colors } from '../styles/colors';

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
  const navigation = useNavigation();

  // get pass/fail stats from results
  let pass = 0;
  let fail = 0;
  results.map(r => {
    if (r.type === 'correct') {
      pass++;
    }
    if (r.type === 'incorrect') {
      fail++;
    }
  });

  return (
    <View style={styles.container}>
      <BouncyCheckbox
        isChecked={value}
        onPress={() => {
          onToggle(description);
        }}
        disableText={true}
        fillColor={colors.blue}
        style={styles.checkbox}
      />
      <TouchableOpacity
        style={styles.touchable}
        onPress={() => {
          // @ts-expect-error - not dealing with navigation types rn
          navigation.navigate('TestDetailsScreen', {
            results,
            suiteName: description,
          });
        }}>
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
  pass: {
    color: colors.green,
  },
  fail: {
    color: colors.red,
  },
  count: {
    fontSize: 12,
    fontWeight: 'bold',
    flex: 1,
    textAlign: 'right',
  },
});
