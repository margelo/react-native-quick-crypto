// import React, { useEffect } from 'react';
// import { View, Text, StyleSheet } from 'react-native';
// import type { RootStackParamList } from '../../RootProps';
// import type { NativeStackScreenProps } from '@react-navigation/native-stack';

// // function getTime(f: () => void): number {
// //   const before = global.performance.now();
// //   f();
// //   const after = global.performance.now();
// //   return after - before;
// // }

// // function cmp(f: () => void, g: () => void) {
// //   return getTime(g) - getTime(f);
// // }

// function startBenchmarking() {}

// type BenchmarksProps = NativeStackScreenProps<RootStackParamList, 'Benchmarks'>;

// export const Benchmarks: React.FC<BenchmarksProps> = () => {
//   useEffect(() => {
//     startBenchmarking();
//   }, []);

//   return (
//     <View style={styles.container}>
//       <Text> Testing performance - You can see results in logs! </Text>
//     </View>
//   );
// };

// const styles = StyleSheet.create({
//   container: {
//     flex: 1,
//     justifyContent: 'center',
//     alignContent: 'center',
//   },
// });
