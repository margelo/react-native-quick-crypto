import React from 'react';
import {View, Text, StyleSheet, TouchableOpacity} from 'react-native';
import BouncyCheckbox from 'react-native-bouncy-checkbox';
import type {BenchmarkResult} from '../types/Results';
import {useNavigation} from '@react-navigation/native';
import type {NativeStackNavigationProp} from '@react-navigation/native-stack';

type BenchmarkItemProps = {
  description: string;
  value: boolean;
  count: number;
  results: BenchmarkResult[];
  onToggle: (description: string) => void;
};

export const BenchmarkItem: React.FC<BenchmarkItemProps> = ({
  description,
  value,
  count,
  results,
  onToggle,
}: BenchmarkItemProps) => {
  const navigation = useNavigation();

  return (
    <View style={styles.container}>
      <BouncyCheckbox
        isChecked={value}
        onPress={() => {
          onToggle(description);
        }}
        disableText={true}
        fillColor="#1976d2"
        style={styles.checkbox}
      />
      <TouchableOpacity
        style={styles.touchable}
        onPress={() => {
          // @ts-ignore
          navigation.navigate('BenchmarkDetailsScreen', {
            results,
            suiteName: description,
          });
        }}>
        <Text style={styles.label} numberOfLines={1}>
          {description}
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
    paddingHorizontal: 10,
  },
  checkbox: {
    transform: [{scaleX: 0.7}, {scaleY: 0.7}],
  },
  label: {
    fontSize: 12,
    flex: 8,
  },
  touchable: {
    flex: 1,
    flexDirection: 'row',
  },
  faster: {
    color: 'green',
  },
  slower: {
    color: 'red',
  },
  count: {
    fontSize: 12,
    fontWeight: 'bold',
    flex: 1,
    textAlign: 'right',
  },
});
