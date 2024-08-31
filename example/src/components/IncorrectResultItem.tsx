import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { colors } from '../styles/colors';

type IncorrectResultItemProps = {
  description: string;
  errorMsg: string;
};

export const IncorrectResultItem: React.FC<IncorrectResultItemProps> = ({
  description,
  errorMsg,
}: IncorrectResultItemProps) => {
  const emoji = '❌';
  const title = emoji + ' [' + description + ']';

  return (
    <View style={styles.itemContainer}>
      <Text style={styles.text}>{title}</Text>
      <Text style={styles.error}>{errorMsg}</Text>
    </View>
  );
};

const styles = StyleSheet.create({
  itemContainer: {
    borderWidth: 1,
    borderRadius: 5,
    padding: 5,
    marginVertical: 5,
  },
  text: {
    flexShrink: 1,
  },
  error: {
    color: colors.red,
  },
});
