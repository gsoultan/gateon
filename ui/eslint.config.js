import jsxA11y from 'eslint-plugin-jsx-a11y'
import tseslint from 'typescript-eslint'
import globals from 'globals'

// Accessibility-focused ESLint configuration.
//
// This config is intentionally scoped to the jsx-a11y rule set (plus the
// TypeScript parser so .tsx files can be parsed). It acts as the CI
// accessibility gate described in doc/recommendations.md (Session 8) without
// pulling in the broad react/typescript rule sets, so the gate stays focused
// on accessibility regressions.
export default [
  {
    ignores: ['dist/**', 'node_modules/**', 'docs/**', 'public/**'],
  },
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
        ecmaFeatures: { jsx: true },
      },
      globals: {
        ...globals.browser,
        ...globals.es2021,
      },
    },
    plugins: {
      'jsx-a11y': jsxA11y,
    },
    rules: {
      ...jsxA11y.flatConfigs.recommended.rules,
    },
  },
]
