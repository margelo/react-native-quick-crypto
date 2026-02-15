import React from 'react';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { StressSuitesScreen } from './StressSuitesScreen';
import { StressDetailsScreen } from './StressDetailsScreen';

const Stack = createNativeStackNavigator();

export const StressStack = () => {
  return (
    <Stack.Navigator>
      <Stack.Screen
        name="StressSuites"
        component={StressSuitesScreen}
        options={{ title: 'Stress Suites' }}
      />
      <Stack.Screen
        name="StressDetailsScreen"
        component={StressDetailsScreen}
        options={{ title: 'Stress Details' }}
      />
    </Stack.Navigator>
  );
};
