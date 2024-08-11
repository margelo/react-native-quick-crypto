import React from 'react';
import {View, Text, StyleSheet} from 'react-native';

type CorrectResultItemProps = {
  description: string;
};

export const CorrectResultItem: React.FC<CorrectResultItemProps> = ({
  description,
}: CorrectResultItemProps) => {
  const emoji = '✅';

  return (
    <View style={styles.itemContainer}>
      <Text style={styles.text}>{emoji}</Text>
      <Text style={styles.text}>{description}</Text>
    </View>
  );
};

const styles = StyleSheet.create({
  itemContainer: {
    flexDirection: 'row',
    paddingHorizontal: 5,
    marginVertical: 2,
  },
  text: {
    flexShrink: 1,
    fontSize: 9,
    paddingRight: 5,
  },
});
