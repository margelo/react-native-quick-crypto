import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import BouncyCheckbox from "react-native-bouncy-checkbox";
import type { TestResult } from '../types/TestResults';
import { useNavigation } from '@react-navigation/native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import type { RootStackParamList } from '../navigators/RootProps';

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
  const navigation =
    useNavigation<NativeStackNavigationProp<RootStackParamList, 'Entry'>>();

  // get pass/fail stats from results
  let pass = 0;
  let fail = 0;
  results.map((r) => {
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
        fillColor='#1976d2'
        style={styles.checkbox}
      />
      <TouchableOpacity
        style={styles.touchable}
        onPress={() => {
          navigation.navigate('TestingScreen', {
            results,
            suiteName: description,
          });
        }}
      >
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
    borderBottomColor: '#ccc',
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
    color: 'green',
  },
  fail: {
    color: 'red',
  },
  count: {
    fontSize: 12,
    fontWeight: 'bold',
    flex: 1,
    textAlign: 'right',
  },
});
