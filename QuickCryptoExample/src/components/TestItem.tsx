import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import Checkbox from '@react-native-community/checkbox';

type TestItemProps = {
  description: string;
  value: boolean;
  index: number;
  onToggle: (index: number) => void;
};

export const TestItem: React.FC<TestItemProps> = ({
  description,
  value,
  index,
  onToggle,
}: TestItemProps) => {
  return (
    <View style={styles.container}>
      <Text>{description}</Text>
      <Checkbox
        value={value}
        onValueChange={() => {
          onToggle(index);
        }}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    width: '100%',
    padding: 10,
    flexDirection: 'row',
    alignContent: 'center',
    alignItems: 'center',
    justifyContent: 'space-evenly',
    backgroundColor: '#99CCFF',
    marginTop: 10,
  },
});
