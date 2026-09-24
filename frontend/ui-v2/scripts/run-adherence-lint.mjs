#!/usr/bin/env node
/**
 * Run design-system adherence lint (rules from _adherence.oxlintrc.json).
 */
import { execFileSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const pkgRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

execFileSync(
  process.platform === 'win32' ? 'npx.cmd' : 'npx',
  [
    'eslint',
    '-c',
    'eslint.adherence.config.js',
    'src/shell/AppShell.tsx',
    'src/design-system',
    'src/routes/PlaceholderRoute.tsx',
  ],
  { cwd: pkgRoot, stdio: 'inherit' },
)
