import React, { useMemo } from 'react';
import { View, FlatList, StyleSheet, Text } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Button } from '../../components/Button';
import { TestItem } from '../../components/TestItem';
import { selectAllSuites, useTestsList } from '../../hooks/useTestsList';
import { useTestsRun } from '../../hooks/useTestsRun';
import type { SuiteEntry } from '../../types/tests';
import { colors } from '../../styles/colors';

export const TestSuitesScreen = (): React.JSX.Element => {
  const [suites, toggle, clearAll, checkAll] = useTestsList();
  const [results, runTests, stats, running] = useTestsRun();

  const suiteEntries = useMemo(() => {
    return Object.entries(suites).map(([name, suite]) => ({
      name,
      suite,
      count: Object.keys(suite.tests).length,
    }));
  }, [suites]);

  const totalCount = useMemo(
    () => suiteEntries.reduce((sum, entry) => sum + entry.count, 0),
    [suiteEntries],
  );

  const renderItem = ({ item, index }: { item: SuiteEntry; index: number }) => (
    <TestItem
      suiteIndex={index}
      description={item.name}
      value={item.suite.value}
      count={item.count}
      results={results[item.name]?.results || []}
      onToggle={toggle}
    />
  );

  return (
    <SafeAreaView style={styles.mainContainer} edges={['left', 'right']}>
      <View style={styles.testList}>
        <FlatList
          data={suiteEntries}
          renderItem={renderItem}
          keyExtractor={(_item, index) => index.toString()}
          testID="test-suites-list"
        />
      </View>
      <TestItem
        suiteIndex={-1}
        isFooter
        description={stats ? `${stats?.duration}ms` : ''}
        count={totalCount}
        passCount={Object.values(results).reduce(
          (sum, suite) =>
            sum + suite.results.filter(r => r.type === 'correct').length,
          0,
        )}
        failCount={Object.values(results).reduce(
          (sum, suite) =>
            sum + suite.results.filter(r => r.type === 'incorrect').length,
          0,
        )}
      />
      {stats ? (
        <Text testID="e2e-completion-summary" style={styles.summary}>
          {`E2E_RESULT status=${stats.failures === 0 ? 'passed' : 'failed'} suites=${stats.suites} failed_suites=${stats.failedSuites} tests=${stats.tests} failures=${stats.failures} duration_ms=${stats.duration}`}
        </Text>
      ) : null}
      <View style={styles.menu}>
        <Button
          title="Clear"
          onPress={clearAll}
          testID="clear-all-button"
          disabled={running}
        />
        <Button
          title={running ? 'Running…' : 'Run Selected'}
          onPress={() => {
            void runTests(suites);
          }}
          color="green"
          testID="run-tests-button"
          disabled={running}
        />
        <Button
          title={running ? 'Running…' : 'Run All'}
          onPress={() => {
            checkAll();
            void runTests(selectAllSuites(suites));
          }}
          color="green"
          testID="run-all-tests-button"
          disabled={running}
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
    borderTopWidth: 1,
    borderTopColor: colors.gray,
    borderBottomWidth: 1,
    borderBottomColor: colors.gray,
  },
  menu: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-around',
    marginVertical: -5,
  },
  summary: {
    fontSize: 10,
    paddingHorizontal: 10,
    paddingVertical: 2,
  },
});
