import js from '@eslint/js';
import typescriptEslint from 'typescript-eslint';

// Import prettier plugin and config directly
import eslintPluginPrettier from 'eslint-plugin-prettier';
import eslintConfigPrettier from 'eslint-config-prettier';

// This is a root-level ESLint config that primarily serves to:
// 1. Enable ESLint to find a config at the root level
// 2. Provide basic linting for files outside workspaces
// 3. Delegate to workspace-specific configs for workspace files

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
  // Ignore workspace-specific config files and node_modules
  {
    ignores: [
      '**/node_modules/**',
      'example/**',
      'packages/**',
      '.vscode/**',
      '*.config.js',
    ],
  },
];
