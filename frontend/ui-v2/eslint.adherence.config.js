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

// ENC-TSK-S64-0B: all of src (was AppShell.tsx and src/design-system only). Existing
// violations are held by the ratchet in scripts/run-adherence-lint.mjs
// (adherence-baseline.json); only new ones fail.
// ENC-TSK-S65-0B: the <Link> prop rules describe the design-system Link (href, variant,
// external, onFollow). react-router's <Link> always takes `to`, which the design-system Link
// does not, so a Link with a `to` prop is excluded rather than reported (41 false positives).
const scopeLinkRules = (rule) =>
  typeof rule === 'object' && rule.selector?.includes("JSXOpeningElement[name.name='Link']")
    ? {
        ...rule,
        selector: rule.selector.replace(
          "JSXOpeningElement[name.name='Link']",
          "JSXOpeningElement[name.name='Link']:not(:has(JSXAttribute[name.name='to']))",
        ),
      }
    : rule

const adherenceTargets = ['src/**/*.{ts,tsx,js}']

export default tseslint.config(
  { ignores: ['dist', 'dev-dist', 'node_modules', 'src/**/*.test.{ts,tsx,js}', 'src/test/**'] },
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
        ? ['error', ...adherence.rules['no-restricted-syntax'].slice(1).map(scopeLinkRules)]
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
