import globals from 'globals'
import tseslint from 'typescript-eslint'
import { createRequire } from 'node:module'

/**
 * ENC-TSK-L18 · design-system adherence guard.
 * Rules are sourced from frontend/design-system-2/_adherence.oxlintrc.json
 * (oxlint-compatible JSON; executed via ESLint because oxlint does not yet
 * implement the no-restricted-syntax selectors in that file).
 */
const require = createRequire(import.meta.url)
const adherence = require('../design-system-2/_adherence.oxlintrc.json')
delete adherence['x-omelette']

const adherenceTargets = [
  'src/shell/AppShell.tsx',
  'src/design-system/**/*.{ts,tsx,js}',
  'src/routes/PlaceholderRoute.tsx',
]

export default tseslint.config(
  { ignores: ['dist', 'dev-dist', 'node_modules'] },
  {
    files: adherenceTargets,
    extends: [...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    rules: {
      'react/forbid-elements': 'off',
      'no-restricted-imports': adherence.rules['no-restricted-imports']
        ? ['error', adherence.rules['no-restricted-imports'][1]]
        : 'off',
      'no-restricted-syntax': adherence.rules['no-restricted-syntax']
        ? ['error', ...adherence.rules['no-restricted-syntax'].slice(1)]
        : 'off',
    },
  },
  {
    files: ['**/index.js'],
    rules: {
      'no-restricted-imports': 'off',
    },
  },
)
