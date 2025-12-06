import React from 'react';
import { View, Text, StyleSheet, FlatList } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { BenchmarkItem } from '../../components/BenchmarkItem';
import { useBenchmarks } from '../../hooks/useBenchmarks';
import { Button } from '../../components/Button';

export const BenchmarkSuitesScreen = () => {
  const [suites, toggle, checkAll, clearAll, runBenchmarks, bumpRunCurrent] =
    useBenchmarks();

  let totalCount = 0;

  return (
    <SafeAreaView style={styles.mainContainer}>
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
                bumpRunCurrent={bumpRunCurrent}
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
        <Button title="Run" onPress={runBenchmarks} color="green" />
      </View>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  mainContainer: {
    flex: 1,
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
