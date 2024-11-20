import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  SafeAreaView,
  TextInput,
  FlatList,
} from 'react-native';
import { BenchmarkItem } from '../../components/BenchmarkItem';
import { colors } from '../../styles/colors';
import { useBenchmarks } from '../../hooks/useBenchmarks';
import { Button } from '../../components/Button';

export const BenchmarkSuitesScreen = () => {
  const [suites, toggle, checkAll, clearAll, runBenchmarks] = useBenchmarks();
  const [multiplier, setMultiplier] = useState<number>(1);

  let totalCount = 0;

  return (
    <SafeAreaView style={styles.mainContainer}>
      <View style={styles.options}>
        <View style={styles.option}>
          <Text style={styles.optionLabel}>run count multiplier</Text>
          <TextInput
            style={styles.textInput}
            value={multiplier.toString()}
            onChangeText={(s: string) => setMultiplier(parseInt(s, 10))}
          />
        </View>
        <Text style={styles.optionCaption}>
          Each benchmark has a distinct run count. If you want to really
          exercise the device, you can increase this number to multiply the run
          count of each benchmark. Recommended values are 1-5.
        </Text>
        <View style={styles.option}></View>
      </View>
      <View style={styles.benchmarkList}>
        <FlatList
          data={suites}
          renderItem={({ item, index }) => {
            const suiteBenchmarkCount = item.benchmarks.length;
            totalCount += suiteBenchmarkCount;
            return (
              <BenchmarkItem
                key={index.toString()}
                suite={item}
                toggle={() => toggle(item.name)}
                multiplier={multiplier}
              />
            );
          }}
        />
      </View>
      <View>
        <Text style={styles.totalCount}>{totalCount}</Text>
      </View>
      <View style={styles.menu}>
        <Button title="Check All" onPress={checkAll} />
        <Button title="Clear All" onPress={clearAll} />
        <Button title="Run" onPress={() => runBenchmarks()} color="green" />
      </View>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  mainContainer: {
    flex: 1,
  },
  options: {
    flex: 1,
    padding: 5,
    borderBottomWidth: 1,
    borderColor: colors.gray,
  },
  option: {
    flexDirection: 'row',
  },
  optionLabel: {
    fontSize: 10,
    fontWeight: 'bold',
    paddingRight: 5,
    alignSelf: 'center',
  },
  optionCaption: {
    fontSize: 8,
    color: colors.darkgray,
    paddingRight: 5,
    alignSelf: 'center',
  },
  textInput: {
    backgroundColor: colors.white,
    borderRadius: 3,
    borderColor: colors.gray,
    borderWidth: 1,
    padding: 5,
    width: 75,
    textAlign: 'right',
  },
  benchmarkList: {
    flex: 9,
  },
  menu: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    alignContent: 'space-around',
    justifyContent: 'space-around',
  },
  totalCount: {
    fontSize: 12,
    fontWeight: 'bold',
    alignSelf: 'flex-end',
    paddingRight: 9,
  },
});
