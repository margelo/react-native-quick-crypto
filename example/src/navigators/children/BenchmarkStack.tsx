import React from 'react'
import { createNativeStackNavigator } from '@react-navigation/native-stack'
import { BenchmarkSuitesScreen } from './BenchmarkSuitesScreen'
import { BenchmarkDetailsScreen } from './BenchmarkDetailsScreen'

const Stack = createNativeStackNavigator()

export const BenchmarkStack = () => {
  return (
    <Stack.Navigator>
      <Stack.Screen
        name="BenchmarkSuites"
        component={BenchmarkSuitesScreen}
        options={{ title: 'Benchmark Suites' }}
      />
      <Stack.Screen
        name="BenchmarkDetailsScreen"
        component={BenchmarkDetailsScreen}
        options={{ title: 'Benchmark Details' }}
      />
    </Stack.Navigator>
  )
}
