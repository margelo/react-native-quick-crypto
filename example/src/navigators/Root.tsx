import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import type { RootStackParamList } from './RootProps';

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
            const { Entry } = require('./children/Entry/Entry');
            return Entry;
          }}
        />
        <Stack.Screen
          name="Benchmarks"
          getComponent={() => {
            const { Benchmarks } = require('./children/benchmarks/Benchmarks');
            return Benchmarks;
          }}
        />
        <Stack.Screen
          name="TestingScreen"
          options={{
            title: 'Tests',
          }}
          getComponent={() => {
            const {
              TestingScreen,
            } = require('./children/TestingScreen/TestingScreen');
            return TestingScreen;
          }}
        />
      </Stack.Navigator>
    </NavigationContainer>
  );
};
