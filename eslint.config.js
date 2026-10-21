// @ts-check
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';

/**
 * ESLint flat config. Zero warnings tolerated (CI runs `--max-warnings 0`).
 * Type-checked rules catch real bug classes (floating promises, unsafe any)
 * in a security tool; tests and plain JS run without type information.
 */
export default tseslint.config(
  {
    ignores: ['**/dist/**', '**/node_modules/**', '**/.next/**', '**/coverage/**', '**/next-env.d.ts']
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    files: ['**/*.ts', '**/*.tsx'],
    languageOptions: {
      parserOptions: {
        projectService: {
          // Root-level tool configs live outside any tsconfig project.
          allowDefaultProject: ['packages/skillsentry/vitest.config.ts']
        },
        tsconfigRootDir: import.meta.dirname
      },
      globals: { ...globals.node, ...globals.browser }
    },
    rules: {
      // `catch {}` swallowing in a parser is deliberate (never crash a scan),
      // but every site must be a conscious choice — empty catches stay visible.
      'no-empty': ['error', { allowEmptyCatch: true }],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/consistent-type-imports': ['error', { prefer: 'type-imports' }],
      'prefer-const': 'error',
      eqeqeq: ['error', 'smart']
    }
  },
  {
    files: ['**/*.test.ts'],
    ...tseslint.configs.disableTypeChecked
  },
  {
    files: ['**/*.js', '**/*.mjs'],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: {
      globals: { ...globals.node }
    }
  }
);
