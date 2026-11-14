#!/usr/bin/env node
/**
 * Design-system adherence lint with a ratchet (ENC-TSK-S64-0B, ENC-PLN-106; was ENC-TSK-L18).
 *
 * Two checks over all of src/ (tests and fixtures excluded):
 *   1. ESLint with the rules from frontend/design-system-2/_adherence.oxlintrc.json
 *      (raw hex, raw px, non-system fonts, design-system component props).
 *   2. A CSS scan of src/**\/*.css for raw color literals (hex, rgb/rgba, including
 *      var() fallbacks), font sizes in px, and deprecated token names (the tokens marked
 *      "Deprecated" in frontend/design-system-2/tokens.json).
 *
 * Existing violations are recorded per file and rule in adherence-baseline.json. A run fails
 * only when a file has MORE violations of a rule than its baseline, so new drift is blocked
 * while old drift is paid down. Counts that fall are reported; rerun with --update-baseline
 * to lock the lower numbers in.
 *
 *   node scripts/run-adherence-lint.mjs                   check (CI: npm run lint:adherence)
 *   node scripts/run-adherence-lint.mjs --update-baseline rewrite adherence-baseline.json
 */
import { execFileSync } from 'node:child_process'
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const pkgRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const baselinePath = path.join(pkgRoot, 'adherence-baseline.json')
const update = process.argv.includes('--update-baseline')

const isTestPath = (p) => /\.test\.[jt]sx?$/.test(p) || p.split(path.sep).includes('test')

/** @type {Record<string, Record<string, number>>} */
const found = {}
const add = (file, key) => {
  const rel = path.relative(pkgRoot, file).split(path.sep).join('/')
  found[rel] ??= {}
  found[rel][key] = (found[rel][key] ?? 0) + 1
}

// 1. ESLint adherence rules over src (tests excluded in eslint.adherence.config.js).
let eslintOut = '[]'
try {
  eslintOut = execFileSync(
    process.platform === 'win32' ? 'npx.cmd' : 'npx',
    ['eslint', '-c', 'eslint.adherence.config.js', '--format', 'json', 'src'],
    { cwd: pkgRoot, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'inherit'] },
  )
} catch (err) {
  // eslint exits 1 when it reports errors; its JSON is still on stdout.
  eslintOut = err.stdout?.toString() || '[]'
}
for (const result of JSON.parse(eslintOut)) {
  for (const m of result.messages) {
    if (m.fatal) {
      console.error(`[adherence] parse error ${result.filePath}:${m.line} ${m.message}`)
      process.exitCode = 2
      continue
    }
    // Only the design-adherence rules count; generic lint (unused vars, plugin rules named in
    // disable comments) belongs to the main eslint config.
    if (m.ruleId !== 'no-restricted-syntax' && m.ruleId !== 'no-restricted-imports') continue
    add(result.filePath, `eslint:${m.ruleId}:${(m.message || '').split(/[—.]/)[0].trim()}`)
  }
}

// 2. CSS scan.
const tokens = JSON.parse(readFileSync(path.join(pkgRoot, '../design-system-2/tokens.json'), 'utf8'))
const deprecated = [
  ...tokens.color.tokens,
  ...(tokens.spacing?.tokens ?? []),
  ...(tokens.radius?.tokens ?? []),
  ...(tokens.shadow?.tokens ?? []),
]
  .filter((t) => /^Deprecated/i.test(t.usage ?? ''))
  .map((t) => t.name)
const deprecatedRe = new RegExp(`var\\(\\s*--(${deprecated.map((n) => n.replace(/[-]/g, '\\-')).join('|')})\\s*[,)]`, 'g')

const walk = (dir) =>
  readdirSync(dir).flatMap((name) => {
    const p = path.join(dir, name)
    return statSync(p).isDirectory() ? walk(p) : [p]
  })

for (const file of walk(path.join(pkgRoot, 'src'))) {
  if (!file.endsWith('.css') || isTestPath(file)) continue
  const css = readFileSync(file, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '')
  for (const _ of css.matchAll(/#[0-9a-fA-F]{3,8}\b/g)) add(file, 'css:raw-color:hex')
  for (const _ of css.matchAll(/\brgba?\(/g)) add(file, 'css:raw-color:rgb')
  for (const _ of css.matchAll(/font-size\s*:\s*[\d.]+px/g)) add(file, 'css:font-size-px')
  for (const _ of css.matchAll(deprecatedRe)) add(file, 'css:deprecated-token')
}

const total = (m) => Object.values(m).reduce((n, byRule) => n + Object.values(byRule).reduce((a, b) => a + b, 0), 0)

if (update) {
  const sorted = Object.fromEntries(Object.keys(found).sort().map((f) => [f, Object.fromEntries(Object.entries(found[f]).sort())]))
  writeFileSync(baselinePath, JSON.stringify(sorted, null, 2) + '\n')
  console.log(`[adherence] baseline written: ${total(found)} violations in ${Object.keys(found).length} files`)
  process.exit(process.exitCode ?? 0)
}

let baseline = {}
try {
  baseline = JSON.parse(readFileSync(baselinePath, 'utf8'))
} catch {
  console.error('[adherence] adherence-baseline.json missing; run with --update-baseline')
  process.exit(1)
}

const regressions = []
let improved = 0
for (const [file, byRule] of Object.entries(found)) {
  for (const [rule, n] of Object.entries(byRule)) {
    const allowed = baseline[file]?.[rule] ?? 0
    if (n > allowed) regressions.push(`${file}: ${rule} ${n} (baseline ${allowed})`)
  }
}
for (const [file, byRule] of Object.entries(baseline)) {
  for (const [rule, n] of Object.entries(byRule)) if ((found[file]?.[rule] ?? 0) < n) improved += n - (found[file]?.[rule] ?? 0)
}

console.log(`[adherence] ${total(found)} violations (baseline ${total(baseline)}); ${improved} fewer than baseline`)
if (improved) console.log('[adherence] counts fell: run `node scripts/run-adherence-lint.mjs --update-baseline` to lock them in')
if (regressions.length) {
  console.error('[adherence] new design-system violations (use role tokens from design-system-2/v2/roles.css):')
  for (const r of regressions) console.error('  ' + r)
  process.exit(1)
}
