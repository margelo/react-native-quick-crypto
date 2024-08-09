import React, {useState} from 'react';
import {SafeAreaView, ScrollView, StyleSheet, Text, View} from 'react-native';
import {BenchmarkResultItem, BenchmarkResultItemHeader} from '../../components/BenchmarkResultItem';
import {BenchmarkResult} from '../../types/Results';

type BenchmarkDetailsScreenProps = {
  route: any;
};

type RouteParams = {
  results: BenchmarkResult[];
  suiteName: string;
};

export const BenchmarkDetailsScreen = ({route}: BenchmarkDetailsScreenProps) => {
  const {results, suiteName}: RouteParams = route.params;

  return (
    <SafeAreaView style={styles.container}>
      <View>
        <Text style={styles.title}>Benchmark Results for '{suiteName}' Suite</Text>
      </View>
      <BenchmarkResultItemHeader />
      <ScrollView
        style={styles.scroll}
        contentContainerStyle={styles.scrollContent}>
        {results.map((it, index: number) => {
          return <BenchmarkResultItem key={index} result={it} />;
        })}
      </ScrollView>
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
  showMenu: {
    flexDirection: 'row',
    width: '100%',
    justifyContent: 'space-evenly',
    paddingBottom: 5,
  },
  showMenuItem: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  showMenuLabel: {
    paddingLeft: 5,
  },
  scroll: {
    width: '100%',
  },
  scrollContent: {
    paddingHorizontal: 5,
  },
});
