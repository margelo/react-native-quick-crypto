import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';
import { colors } from '../styles/colors';

type ButtonProps = {
  title: string;
  onPress: () => void;
  color?: string;
  testID?: string;
  disabled?: boolean;
};

export const Button: React.FC<ButtonProps> = ({
  title,
  onPress,
  color = 'blue',
  testID,
  disabled = false,
}: ButtonProps) => {
  return (
    <View>
      <TouchableOpacity
        style={[
          styles.container,
          { backgroundColor: colors[color] },
          disabled && styles.disabled,
        ]}
        onPress={onPress}
        testID={testID}
        disabled={disabled}
      >
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
  disabled: {
    opacity: 0.5,
  },
});
