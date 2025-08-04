import { fixupPluginRules } from '@eslint/compat';
import js from '@eslint/js';
import eslintReactNative from 'eslint-plugin-react-native';
import typescriptEslint from 'typescript-eslint';

// Import prettier plugin and config directly
import eslintPluginPrettier from 'eslint-plugin-prettier';
import eslintConfigPrettier from 'eslint-config-prettier';

// Create a simplified config array
export default [
  // Base JS config
  js.configs.recommended,

  // TypeScript config
  ...typescriptEslint.configs.recommended,
  {
    languageOptions: {
      parser: typescriptEslint.parser,
      parserOptions: {
        projectService: true,
      },
    },
    plugins: {
      '@typescript-eslint': typescriptEslint.plugin,
    },
  },

  // Prettier integration
  {
    plugins: {
      prettier: eslintPluginPrettier,
    },
    rules: {
      'prettier/prettier': 'error',
    },
  },
  eslintConfigPrettier,
  // React Native config
  {
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
  // Ignore patterns
  {
    ignores: [
      '.prettierrc.js', 
      '*.config.*js', 
      '*.plugin.js', 
      '**/lib/**',
      '**/build/**',
      '**/test/**'],
  },
];
