import React from 'react';
import type { RootStackParamList } from '../../RootProps';
import type {
  NativeStackNavigationProp,
  NativeStackScreenProps,
} from '@react-navigation/native-stack';
import { Text, View, ScrollView, StyleSheet, SafeAreaView } from 'react-native';
import 'mocha';
import { Button } from '../../../components/Button';
import { useNavigation } from '@react-navigation/native';
import { TestItem } from '../../../components/TestItem';
import { useTestList } from '../../../hooks/useTestList';
import { useRunTests } from '../../../hooks/useRunTests';

type EntryProps = NativeStackScreenProps<RootStackParamList, 'Entry'>;

export const Entry: React.FC<EntryProps> = ({}: EntryProps) => {
  const [tests, toggle, clearAll, checkAll] = useTestList();
  const [results, runTests] = useRunTests();
  const navigation =
    useNavigation<NativeStackNavigationProp<RootStackParamList, 'Entry'>>();
  let totalCount = 0;

  return (
    <SafeAreaView style={styles.mainContainer}>
      <View style={styles.testList}>
        <ScrollView style={styles.scrollView}>
          {Object.entries(tests).map(([suiteName, suite]) => {
            totalCount += suite.count;
            return (
              <TestItem
                key={suiteName}
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
            runTests(tests);
          }}
        />
        <Button
          title="Benchmarks"
          onPress={() => {
            navigation.navigate('Benchmarks');
          }}
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
  scrollView: {
    paddingHorizontal: 10,
  },
  totalCount: {
    alignSelf: 'flex-end',
    paddingRight: 20,
  },
});
