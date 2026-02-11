import React, { useMemo } from 'react';
import { View, FlatList, StyleSheet } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Button } from '../../components/Button';
import { TestItem } from '../../components/TestItem';
import { useTestsList } from '../../hooks/useTestsList';
import { useTestsRun } from '../../hooks/useTestsRun';
import { colors } from '../../styles/colors';

type SuiteEntry = {
  name: string;
  suite: { value: boolean; tests: Record<string, () => void | Promise<void>> };
  count: number;
};

export const TestSuitesScreen = () => {
  const [suites, toggle, clearAll, checkAll] = useTestsList();
  const [results, runTests, stats] = useTestsRun();

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
});
