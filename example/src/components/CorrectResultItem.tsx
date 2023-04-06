import React from 'react';
import { View, Text, StyleSheet } from 'react-native';

type CorrectResultItemProps = {
  description: string;
};

export const CorrectResultItem: React.FC<CorrectResultItemProps> = ({
  description,
}: CorrectResultItemProps) => {
  const emoji = '✅';
  const fullText = emoji + ' [' + description + ']';

  return (
    <View style={styles.itemContainer}>
      <Text style={[styles.text]}>{fullText}</Text>
    </View>
  );
};

const styles = StyleSheet.create({
  scroll: {
    flex: 1,
  },
  itemContainer: {
    borderWidth: 1,
    margin: 10,
    flexDirection: 'column',
    borderRadius: 5,
    padding: 5,
  },
  text: {
    flexShrink: 1,
  },
});
