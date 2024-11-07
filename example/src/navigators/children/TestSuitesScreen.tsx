import React from 'react';
import { Text, View, ScrollView, StyleSheet, SafeAreaView } from 'react-native';
import { Button } from '../../components/Button';
import { TestItem } from '../../components/TestItem';
import { useTestsList } from '../../hooks/useTestsList';
import { useTestsRun } from '../../hooks/useTestsRun';

export const TestSuitesScreen = () => {
  const [suites, toggle, clearAll, checkAll] = useTestsList();
  const [results, runTests] = useTestsRun();
  let totalCount = 0;

  return (
    <SafeAreaView style={styles.mainContainer}>
      <View style={styles.testList}>
        <ScrollView style={styles.scrollView}>
          {Object.entries(suites).map(([suiteName, suite], index) => {
            const suiteTestCount = Object.keys(suite.tests).length;
            totalCount += suiteTestCount;
            return (
              <TestItem
                key={index.toString()}
                description={suiteName}
                value={suite.value}
                count={suiteTestCount}
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
            runTests(suites);
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
  testList: {
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
