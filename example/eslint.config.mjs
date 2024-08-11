import { fixupPluginRules } from '@eslint/compat';
import js from '@eslint/js';
import eslintReactNative from 'eslint-plugin-react-native';
import typescriptEslint from 'typescript-eslint';

export default typescriptEslint.config(
  js.configs.recommended,
  ...typescriptEslint.configs.recommendedTypeChecked,
  // react-native
  {
    name: 'eslint-plugin-react-native',
    plugins: {
      'react-native': fixupPluginRules({
        rules: eslintReactNative.rules,
      }),
    },
    rules: {
      ...eslintReactNative.configs.all.rules,
      'react-native/sort-styles': 'off',
      'react-native/no-inline-styles': 'warn',
    },
  },
);