import React, { useContext } from 'react';
import {
  View,
  Text,
  StyleSheet,
  SafeAreaView,
  ScrollView,
  TextInput,
  FlatList,
} from 'react-native';
import { Button } from '../../components/Button';
import { BenchmarkItem } from '../../components/BenchmarkItem';
import { colors } from '../../styles/colors';
import { BenchmarkContext } from '../../components/BenchmarkContext';
// import type { FnResult } from '../../types/results';

export const BenchmarkSuitesScreen = () => {
  const {
    suites,
    toggle,
    clearAll,
    checkAll,
    runCount,
    setRunCount,
    results,
    // setResults,
    // setRunning,
    // addResult,
  } = useContext(BenchmarkContext);
  let totalCount = 0;

  const runBenchmarks = () => {
    console.log('runBenchmarks');
  };

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
        <FlatList
          data={suites}
          renderItem={({ item, index }) => {
            const suiteBenchmarkCount = Object.keys(item.benchmarks).length;
            totalCount += suiteBenchmarkCount;
            return (
              <BenchmarkItem
                key={index.toString()}
                description={item.name}
                value={item.value}
                count={suiteBenchmarkCount}
                results={results[item.name]?.results || []}
                running={item.running}
                onToggle={toggle}
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
        <Button
          title="Run"
          onPress={() => {
            runBenchmarks();
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
