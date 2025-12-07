import React from 'react';
import { Text, View, ScrollView, StyleSheet } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Button } from '../../components/Button';
import { TestItem } from '../../components/TestItem';
import { useTestsList } from '../../hooks/useTestsList';
import { useTestsRun } from '../../hooks/useTestsRun';
import { colors } from '../../styles/colors';

export const TestSuitesScreen = () => {
  const [suites, toggle, clearAll, checkAll] = useTestsList();
  const [results, runTests, stats] = useTestsRun();
  let totalCount = 0;

  return (
    <SafeAreaView style={styles.mainContainer} edges={['left', 'right']}>
      <View style={styles.testList}>
        <ScrollView style={styles.scrollView} testID="test-suites-list">
          {Object.entries(suites).map(([suiteName, suite], index) => {
            const suiteTestCount = Object.keys(suite.tests).length;
            totalCount += suiteTestCount;
            return (
              <TestItem
                key={index.toString()}
                suiteIndex={index}
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
      {results && Object.keys(results).length > 0 && stats && (
        <View style={styles.statsContainer}>
          <Text style={styles.timeLabel}>⏱️ {stats.duration}ms</Text>
          <Text
            style={[styles.pass, styles.statNumber]}
            testID="completion-stats"
          >
            {Object.values(results).reduce(
              (sum, suite) =>
                sum + suite.results.filter(r => r.type === 'correct').length,
              0,
            )}
          </Text>
          <Text
            style={[styles.fail, styles.statNumber]}
            testID="total-fail-count"
          >
            {Object.values(results).reduce(
              (sum, suite) =>
                sum + suite.results.filter(r => r.type === 'incorrect').length,
              0,
            )}
          </Text>
          <Text style={styles.statNumber}>{totalCount}</Text>
        </View>
      )}
      <View style={styles.menu}>
        <Button
          title="Check All"
          onPress={checkAll}
          testID="check-all-button"
        />
        <Button
          title="Clear All"
          onPress={clearAll}
          testID="clear-all-button"
        />
        <Button
          title="Run"
          onPress={() => {
            runTests(suites);
          }}
          color="green"
          testID="run-tests-button"
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
  statsContainer: {
    paddingHorizontal: 10,
    paddingVertical: 5,
    flexDirection: 'row',
    alignItems: 'center',
    alignContent: 'center',
    justifyContent: 'space-evenly',
    gap: 10,
  },
  timeLabel: {
    fontSize: 12,
    fontWeight: 'bold',
    flex: 8,
  },
  statNumber: {
    fontSize: 12,
    fontWeight: 'bold',
    flex: 1,
    textAlign: 'right',
  },
  pass: {
    color: colors.green,
  },
  fail: {
    color: colors.red,
  },
});
