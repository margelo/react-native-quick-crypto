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
        <Text>{title}</Text>
      </TouchableOpacity>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    backgroundColor: '#99FFFF',
    padding: 10,
    borderRadius: 5,
    alignContent: 'center',
    justifyContent: 'center',
    borderWidth: 1,
    borderColor: 'black',
  },
});
