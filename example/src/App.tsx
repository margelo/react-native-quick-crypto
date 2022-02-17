import * as React from 'react';

import { StyleSheet, View, Text } from 'react-native';
import { FastCrypto } from 'react-native-fast-crypto';

// Uncomment to run benchmark
// import { benchmarkAgainstOldCrypto } from './Benchmarks';
// setTimeout(async () => {
//   await benchmarkAgainstOldCrypto();
// }, 5000);

export default function App() {
  return (
    <View style={styles.container}>
      <Text>
        Hello!{' '}
        {FastCrypto == null
          ? 'FastCrypto is null :('
          : 'FastCrypto is installed!'}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: 20,
  },
  keys: {
    fontSize: 14,
    color: 'grey',
  },
  title: {
    fontSize: 16,
    color: 'black',
    marginRight: 10,
  },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  textInput: {
    flex: 1,
    marginVertical: 20,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: 'black',
    borderRadius: 5,
    padding: 10,
  },
});
