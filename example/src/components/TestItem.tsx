import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import BouncyCheckbox from 'react-native-bouncy-checkbox';
import type { TestResult } from '../types/Results';
import { useNavigation } from '@react-navigation/native';
import { colors } from '../styles/colors';

type TestItemProps = {
  suiteIndex?: number;
  description: string;
  value?: boolean;
  count: number;
  results?: TestResult[];
  onToggle?: (description: string) => void;
  isFooter?: boolean;
  passCount?: number;
  failCount?: number;
  detailsScreen?: string;
};

export const TestItem: React.FC<TestItemProps> = ({
  suiteIndex = 0,
  description,
  value = false,
  count,
  results = [],
  onToggle,
  isFooter = false,
  passCount,
  failCount,
  detailsScreen = 'TestDetailsScreen',
}: TestItemProps) => {
  const navigation = useNavigation();

  // get pass/fail stats from results
  let pass = passCount ?? 0;
  let fail = failCount ?? 0;

  if (!isFooter) {
    results.map(r => {
      if (r.type === 'correct') {
        pass++;
      }
      if (r.type === 'incorrect') {
        fail++;
      }
    });
  }

  return (
    <View style={styles.container}>
      {isFooter ? (
        <Text style={styles.timer}>⏱️</Text>
      ) : (
        <BouncyCheckbox
          isChecked={value}
          onPress={() => {
            onToggle?.(description);
          }}
          fillColor={colors.blue}
          style={styles.checkbox}
          disableBuiltInState={true}
        />
      )}
      <TouchableOpacity
        style={styles.touchable}
        onPress={() => {
          if (!isFooter) {
            // @ts-expect-error - not dealing with navigation types rn
            navigation.navigate(detailsScreen, {
              results,
              suiteName: description,
            });
          }
        }}
      >
        <Text
          style={styles.label}
          numberOfLines={1}
          testID={`test-suite-${suiteIndex}-name`}
        >
          {description}
        </Text>
        <Text
          style={[styles.pass, styles.count]}
          numberOfLines={1}
          testID={
            isFooter
              ? 'completion-stats'
              : `test-suite-${suiteIndex}-pass-count`
          }
        >
          {isFooter ? pass : pass || ''}
        </Text>
        <Text
          style={[styles.fail, styles.count]}
          numberOfLines={1}
          testID={
            isFooter
              ? 'total-fail-count'
              : `test-suite-${suiteIndex}-fail-count`
          }
        >
          {isFooter ? fail : fail || ''}
        </Text>
        <Text
          style={styles.count}
          numberOfLines={1}
          testID={
            isFooter
              ? 'total-test-count'
              : `test-suite-${suiteIndex}-total-count`
          }
        >
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
    marginVertical: -1,
  },
  checkbox: {
    transform: [{ scaleX: 0.6 }, { scaleY: 0.6 }],
  },
  label: {
    fontSize: 11,
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
    fontSize: 11,
    flex: 1,
    textAlign: 'right',
    paddingHorizontal: 1,
  },
  timer: {
    fontSize: 14,
    paddingHorizontal: 6,
    paddingVertical: 4,
  },
});
