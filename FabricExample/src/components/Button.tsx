import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';

type ButtonProps = {
  title: string;
  onPress: () => void;
};

export const Button: React.FC<ButtonProps> = ({
  title,
  onPress,
}: ButtonProps) => {
  return (
    <View>
      <TouchableOpacity style={styles.container} onPress={onPress}>
        <Text style={styles.label}>{title}</Text>
      </TouchableOpacity>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    backgroundColor: '#1976d2',
    padding: 10,
    borderRadius: 5,
    alignContent: 'center',
    justifyContent: 'center',
  },
  label: {
    color: 'white',
  },
});
