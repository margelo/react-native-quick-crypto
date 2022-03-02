import React, { useEffect, useState, useCallback, useRef } from 'react';
import { View, ScrollView, StyleSheet, Text } from 'react-native';
import type { TestResult } from './TestResult';
import { testLib } from './MochaSetup';

function useTestResults(): [TestResult[], (newResult: TestResult) => void] {
  const [results, setResults] = useState<TestResult[]>([]);

  let viewIsMounted = useRef(true);

  useEffect(() => {
    return () => {
      viewIsMounted.current = false;
    };
  }, []);

  const addResult = useCallback(
    (newResult: TestResult) => {
      if (!viewIsMounted.current) {
        return;
      }
      setResults((prevResults) => {
        prevResults.push(newResult);
        return [...prevResults]; // had to copy to trigger rerender
      });
    },
    [setResults]
  );

  return [results, addResult];
}

function Item({ result }: { result: TestResult }): React.ReactElement {
  return (
    <View style={styles.itemContainer}>
      <Text> {result.name} </Text>
      <Text style={styles.text}>
        {result.status === 'correct' && '😎'}
        {result.status === 'incorrect' && ' -> ' + result!.errorMsg + ' 😬'}
      </Text>
    </View>
  );
}

export function Tests(): React.ReactElement {
  const [results, addResult] = useTestResults();

  useEffect(() => {
    testLib(addResult);
  }, [addResult]);

  return (
    <ScrollView>
      {results.map((it: TestResult) => {
        return <Item result={it} key={it.key} />;
      })}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  itemContainer: {
    flexDirection: 'row',
    width: '80%',
    borderWidth: 1,
    margin: 10,
  },
  text: {
    flexWrap: 'wrap',
    flexShrink: 1,
  },
});
