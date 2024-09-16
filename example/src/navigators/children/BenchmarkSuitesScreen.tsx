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
  const [challenger, setChallenger] = useState<string>('crypto-browserify');
  const [benchmarks, toggle, clearAll, checkAll] =
    useBenchmarksList(challenger);
  const [results, runBenchmarks] = useBenchmarksRun(runCount);
  let totalCount = 0;

  return (
    <SafeAreaView style={styles.mainContainer}>
      <View style={styles.options}>
        <View style={styles.option}>
          <Text style={styles.optionLabel}>run count</Text>
          <TextInput
            value={runCount.toString()}
            onChangeText={(s: string) => setRunCount(parseInt(s, 10))}
          />
        </View>
        <View style={styles.option}>
          <Text style={styles.optionLabel}>challenger</Text>
          <TextInput value={challenger} onChangeText={setChallenger} />
        </View>
      </View>
      <View style={styles.benchmarkList}>
        <ScrollView style={styles.scrollView}>
          {Object.entries(benchmarks).map(([suiteName, suite], index) => {
            totalCount += suite.count;
            return (
              <BenchmarkItem
                key={index.toString()}
                description={suiteName}
                value={suite.value}
                count={suite.count}
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
    paddingTop: 5,
    maxHeight: 60,
    borderBottomWidth: 1,
    borderColor: colors.gray,
  },
  option: {},
  optionLabel: {
    fontSize: 10,
    fontWeight: 'bold',
    alignSelf: 'flex-start',
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
