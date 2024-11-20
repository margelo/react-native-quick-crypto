import React from 'react';
import { FlatList, SafeAreaView, StyleSheet, Text, View } from 'react-native';
import {
  BenchmarkResultItem,
  BenchmarkResultItemHeader,
} from '../../components/BenchmarkResultItem';
import type { BenchmarkResult } from '../../types/benchmarks';

// @ts-expect-error - not dealing with navigation types rn
type BenchmarkDetailsScreenProps = { route };

type RouteParams = {
  results: BenchmarkResult[];
  name: string;
};

export const BenchmarkDetailsScreen = ({
  route,
}: BenchmarkDetailsScreenProps) => {
  const { results, name }: RouteParams = route.params;

  return (
    <SafeAreaView style={styles.container}>
      <View>
        <Text style={styles.title}>Benchmark Results for '{name}' Suite</Text>
      </View>
      <BenchmarkResultItemHeader />
      <FlatList
        style={styles.scroll}
        contentContainerStyle={styles.scrollContent}
        data={results}
        renderItem={({
          item,
          index,
        }: {
          item: BenchmarkResult;
          index: number;
        }) => <BenchmarkResultItem key={index} result={item} />}
      />
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    paddingBottom: 30,
  },
  title: {
    textAlign: 'center',
    paddingVertical: 5,
  },
  scroll: {
    width: '100%',
  },
  scrollContent: {
    paddingHorizontal: 5,
  },
});
