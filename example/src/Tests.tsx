import React, { useEffect, useState, useCallback, useRef } from 'react';
import { View, ScrollView, StyleSheet, Text } from 'react-native';
import type { TestResult } from './TestResult';
import { testLib } from './MochaSetup';
import { useMemo } from 'react';

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
  const text = useMemo(() => {
    let emoji = result.status === 'correct' ? '😎' : '😬';
    const fullText =
      emoji + ' [' + result.name + '] -----> ' + result?.errorMsg + ' ';
    return fullText;
  }, [result]);
  return (
    <View style={styles.itemContainer}>
      <Text style={[styles.text]}>{text}</Text>
    </View>
  );
}

export function Tests(): React.ReactElement {
  const [results, addResult] = useTestResults();

  useEffect(() => {
    testLib(addResult);
  }, [addResult]);

  return (
    <ScrollView style={styles.scroll}>
      {results.map((it: TestResult) => {
        return <Item result={it} key={it.key} />;
      })}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  scroll: {
    flex: 1,
  },
  itemContainer: {
    borderWidth: 1,
    margin: 10,
    flexDirection: 'column',
  },
  text: {
    flexShrink: 1,
  },
});
