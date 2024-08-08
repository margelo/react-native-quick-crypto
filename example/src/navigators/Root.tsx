import React from 'react';
import {NavigationContainer} from '@react-navigation/native';
import {enableFreeze} from 'react-native-screens';
import {TestStack} from './children/TestStack';
import {BenchmarkSuitesScreen} from './children/BenchmarkSuitesScreen';
import {createBottomTabNavigator} from '@react-navigation/bottom-tabs';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';

enableFreeze(true);
const Tab = createBottomTabNavigator();

export const Root: React.FC = () => {
  return (
    <NavigationContainer>
      <Tab.Navigator initialRouteName="Benchmarks">
        <Tab.Screen
          name="Tests"
          component={TestStack}
          options={{
            headerShown: false,
            tabBarIcon: ({color}) => (
              <Icon name="test-tube" size={24} color={color} />
            ),
          }}
        />
        <Tab.Screen
          name="Benchmarks"
          component={BenchmarkSuitesScreen}
          options={{
            title: 'Benchmarks',
            tabBarIcon: ({color}) => (
              <Icon name="timer" size={24} color={color} />
            ),
          }}
        />
      </Tab.Navigator>
    </NavigationContainer>
  );
};
