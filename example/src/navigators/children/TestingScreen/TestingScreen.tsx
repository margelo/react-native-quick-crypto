import React, { useState, useCallback, useRef, useEffect } from 'react';
import type { RootStackParamList } from '../../RootProps';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import { View, ScrollView, StyleSheet } from 'react-native';
import type { RowItemType } from './RowItemType';
import { testLib } from '../../../testing/MochaSetup';
import { Indentator } from '../../../components/Indentator';
import { CorrectResultItem } from '../../../components/CorrectResultItem';
import { IncorrectResultItem } from '../../../components/IncorrectResultItem';
import { Suite } from '../../../components/Suite';

function useTestRows(): [RowItemType[], (newResult: RowItemType) => void] {
  const [rows, setRows] = useState<RowItemType[]>([]);

  let viewIsMounted = useRef(true);

  useEffect(() => {
    return () => {
      viewIsMounted.current = false;
    };
  }, []);

  const addResult = useCallback(
    (newResult: RowItemType) => {
      if (!viewIsMounted.current) {
        return;
      }
      setRows((prevRows) => {
        prevRows.push(newResult);
        return [...prevRows]; // had to copy to trigger rerender
      });
    },
    [setRows]
  );

  return [rows, addResult];
}

type TestingScreenProps = NativeStackScreenProps<
  RootStackParamList,
  'TestingScreen'
>;

export const TestingScreen: React.FC<TestingScreenProps> = ({
  route,
}: TestingScreenProps) => {
  const { testRegistrators } = route.params;
  const [rows, addRow] = useTestRows();

  useEffect(() => {
    const abort = testLib(addRow, testRegistrators);
    return () => {
      abort();
    };
  }, [addRow, testRegistrators]);

  return (
    <ScrollView
      style={styles.scroll}
      contentContainerStyle={styles.scrollContent}
    >
      {rows.map((it) => {
        let InnerElement = <View />;
        if (it.type === 'correct') {
          InnerElement = <CorrectResultItem description={it.description} />;
        }
        if (it.type === 'incorrect') {
          const errorMsg = it.errorMsg || ''; // Trick TS - How to do it as it should be? :)
          InnerElement = (
            <IncorrectResultItem
              description={it.description}
              errorMsg={errorMsg}
            />
          );
        }
        if (it.type === 'grouping') {
          InnerElement = <Suite description={it.description} />;
        }
        return (
          <Indentator key={it.key} indentation={it.indentation}>
            {InnerElement}
          </Indentator>
        );
      })}
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  testList: {
    flex: 9,
  },
  menu: {
    flex: 1,
    alignItems: 'center',
    alignContent: 'center',
    justifyContent: 'center',
  },
  scroll: {
    width: '100%',
  },
  scrollContent: {
    padding: 5,
  },
});
