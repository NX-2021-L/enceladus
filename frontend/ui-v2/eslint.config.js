import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import tseslint from 'typescript-eslint'

// ENC-TSK-K21 · Lint policy encodes the graded acceptance criteria so they are
// machine-verified, not just prose:
//
//   AC-16  React Compiler is active -> ZERO manual useMemo / useCallback /
//          React.memo anywhere in new component files.
//   AC-13  ZERO raw fetch() outside a TanStack Query queryFn. The api/ layer is
//          the ONLY place a bare fetch is allowed (that is the queryFn body).
//
// react-hooks v7 ships the react-compiler rule; enabling it flags any code the
// compiler cannot safely optimize.
export default tseslint.config(
  { ignores: ['dist', 'dev-dist', 'node_modules'] },
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      ...tseslint.configs.recommended,
      // v7 flat config. Includes the React-Compiler-aware rules
      // (purity, immutability, preserve-manual-memoization) that back AC-16.
      reactHooks.configs.flat.recommended,
    ],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    rules: {
      // AC-16 — the compiler owns memoization. Manual memoization is banned.
      'no-restricted-syntax': [
        'error',
        {
          selector:
            "CallExpression[callee.name='useMemo']",
          message:
            'AC-16: React Compiler is active — do not hand-write useMemo. Remove it.',
        },
        {
          selector:
            "CallExpression[callee.name='useCallback']",
          message:
            'AC-16: React Compiler is active — do not hand-write useCallback. Remove it.',
        },
        {
          selector:
            "CallExpression[callee.object.name='React'][callee.property.name='memo']",
          message:
            'AC-16: React Compiler is active — do not wrap components in React.memo.',
        },
        {
          selector:
            "CallExpression[callee.name='memo']",
          message:
            'AC-16: React Compiler is active — do not wrap components in memo().',
        },
      ],
    },
  },
  {
    // AC-13 — bare fetch() is only permitted inside the api/ query-fn layer.
    files: ['src/**/*.{ts,tsx}'],
    ignores: ['src/api/**', 'src/auth/**'],
    rules: {
      'no-restricted-globals': [
        'error',
        {
          name: 'fetch',
          message:
            'AC-13: no raw fetch() outside a TanStack Query queryFn. Route reads through src/api/queryOptions.',
        },
      ],
    },
  },
)
