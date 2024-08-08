import {createNativeStackNavigator} from '@react-navigation/native-stack';
import { TestSuitesScreen } from './TestSuitesScreen';
import { TestDetailsScreen } from './TestDetailsScreen';

const Stack = createNativeStackNavigator();

export const TestStack = () => {
  return (
    <Stack.Navigator>
      <Stack.Screen
        name="TestSuites"
        component={ TestSuitesScreen }
        options={{ title: 'Test Suites' }}
      />
      <Stack.Screen
        name="TestDetailsScreen"
        component={ TestDetailsScreen }
        options={{ title: 'Test Details' }}
      />
    </Stack.Navigator>
  );
};
