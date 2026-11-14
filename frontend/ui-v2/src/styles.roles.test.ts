// ENC-TSK-S60-0A: the v1.1 role tier is generated from design-system-2/tokens.json and
// loaded by styles.css. These checks keep the generated file current and additive.
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const here = dirname(fileURLToPath(import.meta.url))
const ds = resolve(here, '../../design-system-2')
const rolesCss = readFileSync(resolve(ds, 'v2/roles.css'), 'utf8')
const tokens = JSON.parse(readFileSync(resolve(ds, 'tokens.json'), 'utf8')) as {
  color: { tokens: { name: string }[] }
}

const defined = (css: string) => new Set([...css.matchAll(/--([a-z0-9_-]+)\s*:/g)].map((m) => m[1]))

describe('v1.1 role tokens (roles.css)', () => {
  it('is current with tokens.json', () => {
    expect(() =>
      execFileSync(process.execPath, [resolve(ds, 'scripts/build-roles-css.mjs'), '--check'], { stdio: 'pipe' }),
    ).not.toThrow()
  })

  it('is imported by the app stylesheet after the two existing token files', () => {
    const styles = readFileSync(resolve(here, 'styles.css'), 'utf8')
    const order = ['colors_and_type.css', 'v2/tokens.css', 'v2/roles.css'].map((f) => styles.indexOf(f))
    expect(order.every((i) => i >= 0)).toBe(true)
    expect(order).toEqual([...order].sort((a, b) => a - b))
  })

  it('defines every color token in tokens.json across the three token files', () => {
    const all = new Set([
      ...defined(readFileSync(resolve(ds, 'colors_and_type.css'), 'utf8')),
      ...defined(readFileSync(resolve(ds, 'v2/tokens.css'), 'utf8')),
      ...defined(rolesCss),
    ])
    const missing = tokens.color.tokens.map((t) => t.name).filter((n) => !all.has(n))
    expect(missing).toEqual([])
  })

  it('resolves the names the app used before they existed', () => {
    const names = defined(rolesCss)
    for (const n of [
      'border',
      'focus',
      'accent-secondary',
      'bg-elevated',
      'bg-inset',
      'bg-void',
      'status-success-fg',
      'status-warning-fg',
      'status-danger-fg',
    ]) {
      expect(names.has(n), n).toBe(true)
    }
  })

  it('carries the nine status roles with text, border, fill and dot', () => {
    const names = defined(rolesCss)
    for (const role of ['todo', 'active', 'caution', 'waiting', 'done', 'live', 'failed', 'retired', 'unknown']) {
      for (const part of ['text', 'border', 'fill', 'dot']) expect(names.has(`status-${role}-${part}`), `${role}-${part}`).toBe(true)
    }
  })
})
