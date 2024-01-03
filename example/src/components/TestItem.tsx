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
      <Checkbox
        value={value}
        onValueChange={() => {
          onToggle(index);
        }}
      />
      <Text style={styles.label}>{description}</Text>
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
    marginTop: 10,
    gap: 20,
    borderBottomWidth: 1,
    borderBottomColor: '#ccc',
  },
  label: {
    flex: 1,
  },
});
