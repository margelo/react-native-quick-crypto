import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import type { RootStackParamList } from './RootProps';
import { enableFreeze } from "react-native-screens";
import { TestingScreen } from './children/TestingScreen/TestingScreen';
import { Entry } from './children/Entry/Entry';

enableFreeze(true);
const Stack = createNativeStackNavigator<RootStackParamList>();

export const Root: React.FC = () => {
  return (
    <NavigationContainer>
      <Stack.Navigator>
        <Stack.Screen
          name="Entry"
          component={ Entry }
          options={{ title: 'Test Suites' }}
        />
        {/* <Stack.Screen
          name="Benchmarks"
          component={ Benchmarks }
          options={{ title: 'Benchmarks' }}
        /> */}
        <Stack.Screen
          name="TestingScreen"
          component={ TestingScreen }
          options={{ title: 'Tests' }}
        />
      </Stack.Navigator>
    </NavigationContainer>
  );
};
