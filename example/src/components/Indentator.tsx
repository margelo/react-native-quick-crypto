import React from 'react';
import { View, StyleSheet } from 'react-native';

type IndentatorProps = {
  indentation: number;
  children: React.ReactChild;
};

export const Indentator: React.FC<IndentatorProps> = ({
  indentation,
  children,
}: IndentatorProps) => {
  return (
    <View style={styles.container}>
      <View style={{ width: indentation * 40 }} />
      <View style={styles.result}>{children}</View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    width: '100%',
    flexDirection: 'row',
    alignContent: 'center',
  },
  result: {
    flex: 1,
  },
});
