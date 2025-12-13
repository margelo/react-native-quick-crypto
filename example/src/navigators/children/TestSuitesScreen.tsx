import React, { useMemo } from 'react';
import {
  Text,
  View,
  FlatList,
  StyleSheet,
  TouchableOpacity,
} from 'react-native';
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
      {results && Object.keys(results).length > 0 && stats && (
        <View style={styles.footerItem}>
          <View style={styles.footerCheckbox} />
          <TouchableOpacity style={styles.footerContent} activeOpacity={1}>
            <Text style={styles.footerLabel}>⏱️ {stats.duration}ms</Text>
            <Text
              style={[styles.pass, styles.footerCount]}
              testID="completion-stats"
            >
              {Object.values(results).reduce(
                (sum, suite) =>
                  sum + suite.results.filter(r => r.type === 'correct').length,
                0,
              )}
            </Text>
            <Text
              style={[styles.fail, styles.footerCount]}
              testID="total-fail-count"
            >
              {Object.values(results).reduce(
                (sum, suite) =>
                  sum +
                  suite.results.filter(r => r.type === 'incorrect').length,
                0,
              )}
            </Text>
            <Text style={styles.footerCount} testID="total-test-count">
              {totalCount}
            </Text>
          </TouchableOpacity>
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
  footerItem: {
    width: '100%',
    flexDirection: 'row',
    alignContent: 'center',
    alignItems: 'center',
    gap: 10,
    borderTopWidth: 1,
    borderTopColor: colors.gray,
    paddingHorizontal: 10,
    paddingVertical: 5,
  },
  footerCheckbox: {
    width: 24,
  },
  footerContent: {
    flex: 1,
    flexDirection: 'row',
  },
  footerLabel: {
    fontSize: 11,
    fontWeight: 'bold',
    flex: 8,
  },
  footerCount: {
    fontSize: 11,
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
