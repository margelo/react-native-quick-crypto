import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import type { RootStackParamList } from './RootProps';
import { Entry } from './children/Entry/Entry';
import { Benchmarks } from './children/benchmarks/Benchmarks';
import { TestingScreen } from './children/TestingScreen/TestingScreen';

const Stack = createNativeStackNavigator<RootStackParamList>();

export const Root: React.FC = () => {
  return (
    <NavigationContainer>
      <Stack.Navigator>
        <Stack.Screen
          name="Entry"
          options={{
            title: 'Test Suites',
          }}
          getComponent={() => {
            return Entry;
          }}
        />
        <Stack.Screen
          name="Benchmarks"
          getComponent={() => {
            return Benchmarks;
          }}
        />
        <Stack.Screen
          name="TestingScreen"
          options={{
            title: 'Tests',
          }}
          getComponent={() => {
            return TestingScreen;
          }}
        />
      </Stack.Navigator>
    </NavigationContainer>
  );
};
