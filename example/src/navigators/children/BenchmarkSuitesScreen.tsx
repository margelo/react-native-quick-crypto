import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  SafeAreaView,
  ScrollView,
  TextInput,
} from 'react-native';
import { Button } from '../../components/Button';
import { BenchmarkItem } from '../../components/BenchmarkItem';
import { useBenchmarksList } from '../../hooks/useBenchmarksList';
import { useBenchmarksRun } from '../../hooks/useBenchmarksRun';
import { colors } from '../../styles/colors';

export const BenchmarkSuitesScreen = () => {
  const [runCount, setRunCount] = useState<number>(1000);
  const [benchmarks, toggle, clearAll, checkAll] = useBenchmarksList();
  const [results, runBenchmarks] = useBenchmarksRun(runCount);
  let totalCount = 0;

  return (
    <SafeAreaView style={styles.mainContainer}>
      <View style={styles.options}>
        <View style={styles.option}>
          <Text style={styles.optionLabel}>run count</Text>
          <TextInput
            style={styles.textInput}
            value={runCount.toString()}
            onChangeText={(s: string) => setRunCount(parseInt(s, 10))}
          />
        </View>
        <View style={styles.option}></View>
      </View>
      <View style={styles.benchmarkList}>
        <ScrollView style={styles.scrollView}>
          {Object.entries(benchmarks).map(([suiteName, suite], index) => {
            const suiteBenchmarkCount = Object.keys(suite.benchmarks).length;
            totalCount += suiteBenchmarkCount;
            return (
              <BenchmarkItem
                key={index.toString()}
                description={suiteName}
                value={suite.value}
                count={suiteBenchmarkCount}
                results={results[suiteName]?.results || []}
                onToggle={toggle}
              />
            );
          })}
        </ScrollView>
      </View>
      <View>
        <Text style={styles.totalCount}>{totalCount}</Text>
      </View>
      <View style={styles.menu}>
        <Button title="Check All" onPress={checkAll} />
        <Button title="Clear All" onPress={clearAll} />
        <Button
          title="Run"
          onPress={() => {
            runBenchmarks(benchmarks);
          }}
          color="green"
        />
      </View>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  mainContainer: {
    flex: 1,
  },
  options: {
    flex: 2,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-around',
    // paddingTop: 5,
    maxHeight: 45,
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
  scrollView: {},
  totalCount: {
    fontSize: 12,
    fontWeight: 'bold',
    alignSelf: 'flex-end',
    paddingRight: 9,
  },
});
