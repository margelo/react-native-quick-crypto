import React from 'react';
import { TouchableOpacity, View, StyleSheet } from 'react-native';
import type { StyleProp, ViewStyle } from 'react-native';
import { colors } from '../styles/colors';

type CheckboxProps = {
  isChecked: boolean;
  onPress: () => void;
  fillColor?: string;
  size?: number;
  testID?: string;
  disableText?: boolean;
  style?: StyleProp<ViewStyle>;
};

export const Checkbox: React.FC<CheckboxProps> = ({
  isChecked,
  onPress,
  fillColor = colors.blue,
  size = 25,
  style,
  testID,
}) => {
  return (
    <TouchableOpacity
      style={[styles.container, style, { width: size, height: size }]}
      onPress={onPress}
      testID={testID}
      activeOpacity={0.7}
    >
      <View
        style={[
          styles.box,
          {
            borderColor: fillColor,
            backgroundColor: isChecked ? fillColor : colors.transparent,
            width: size,
            height: size,
          },
        ]}
      >
        {isChecked && <View style={styles.checkmark} />}
      </View>
    </TouchableOpacity>
  );
};

const styles = StyleSheet.create({
  container: {
    justifyContent: 'center',
    alignItems: 'center',
  },
  box: {
    borderWidth: 2,
    justifyContent: 'center',
    alignItems: 'center',
    borderRadius: 4,
  },
  checkmark: {
    width: '60%',
    height: '30%',
    borderBottomWidth: 2,
    borderLeftWidth: 2,
    borderColor: colors.white,
    transform: [{ rotate: '-45deg' }, { translateY: -2 }],
  },
});
