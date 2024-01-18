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

type EntryProps = NativeStackScreenProps<RootStackParamList, 'Entry'>;

export const Entry: React.FC<EntryProps> = ({}: EntryProps) => {
  const [tests, toggle, clearAll, checkAll, totalCount] = useTestList();
  const navigation =
    useNavigation<NativeStackNavigationProp<RootStackParamList, 'Entry'>>();
  return (
    <SafeAreaView style={styles.mainContainer}>
      <View style={styles.testList}>
        <ScrollView style={styles.scrollView}>
          {tests.map((test, index: number) => {
            // console.log({ test });
            return (
              <TestItem
                key={index.toString()}
                index={index}
                description={test.description}
                value={test.value}
                count={test.count}
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
            navigation.navigate('TestingScreen', {
              testRegistrators: tests
                .filter((it) => it.value)
                .map((it) => it.registrator),
            });
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
