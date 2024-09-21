import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';
import { colors } from '../styles/colors';

type ButtonProps = {
  title: string;
  onPress: () => void;
  color?: string;
};

export const Button: React.FC<ButtonProps> = ({
  title,
  onPress,
  color = 'blue',
}: ButtonProps) => {
  return (
    <View>
      <TouchableOpacity
        style={[styles.container, { backgroundColor: colors[color] }]}
        onPress={onPress}>
        <Text style={styles.label}>{title}</Text>
      </TouchableOpacity>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    padding: 10,
    borderRadius: 5,
    alignContent: 'center',
    justifyContent: 'center',
    minWidth: 100,
  },
  label: {
    color: colors.white,
    alignSelf: 'center',
  },
});
