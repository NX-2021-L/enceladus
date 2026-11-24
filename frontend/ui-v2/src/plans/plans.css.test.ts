import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

/**
 * ENC-TSK-S98-0B (ENC-PLN-108 W3.2), acceptance criteria 2 and 3: plans.css is the approved stylesheet, so it carries no
 * colour literal and no keyframes, every token it reads exists, and the wave toggle overlay and the record link above it are
 * the mechanism the canvas specifies.
 *
 * jsdom does not lay out CSS or evaluate container queries, so the width-dependent rules are checked by cascading the
 * `@container` blocks of the file itself at a given card width (`widthRules`). That tests what the stylesheet says at each
 * boundary; it does not measure a rendered pixel.
 */
const here = dirname(fileURLToPath(import.meta.url))
const css = readFileSync(resolve(here, 'plans.css'), 'utf8')
const stripped = css.replace(/\/\*[\s\S]*?\*\//g, '')

/** Top-level rules and @container blocks of a stylesheet that has no other at-rules to nest. */
interface Rule {
  selector: string
  decls: Record<string, string>
}
const parseDecls = (body: string): Record<string, string> => {
  const out: Record<string, string> = {}
  for (const part of body.split(';')) {
    const i = part.indexOf(':')
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim()
  }
  return out
}
const parseRules = (text: string): Rule[] => {
  const rules: Rule[] = []
  for (const m of text.matchAll(/([^{}@]+)\{([^{}]*)\}/g)) rules.push({ selector: (m[1] as string).trim(), decls: parseDecls(m[2] as string) })
  return rules
}
const containerBlocks = [...stripped.matchAll(/@container\s*\(min-width:\s*(\d+)px\)\s*\{((?:[^{}]*\{[^{}]*\})*)\s*\}/g)].map((m) => ({
  minWidth: Number(m[1]),
  rules: parseRules(m[2] as string),
}))
const baseRules = parseRules(stripped.replace(/@container[^{]*\{(?:[^{}]*\{[^{}]*\})*\s*\}/g, '').replace(/@media[^{]*\{(?:[^{}]*\{[^{}]*\})*\s*\}/g, '').replace(/@starting-style\s*\{(?:[^{}]*\{[^{}]*\})*\s*\}/g, ''))

/** The value of `prop` for `selector` at a card width: the base rule, then each applicable @container block in source order. */
function widthRule(selector: string, prop: string, cardWidth: number): string | undefined {
  let value: string | undefined
  for (const r of baseRules) if (r.selector.split(',').map((s) => s.trim()).includes(selector) && prop in r.decls) value = r.decls[prop]
  for (const b of containerBlocks) {
    if (b.minWidth > cardWidth) continue
    for (const r of b.rules) if (r.selector.split(',').map((s) => s.trim()).includes(selector) && prop in r.decls) value = r.decls[prop]
  }
  return value
}

describe('plans.css (acceptance criterion 2: no colour literal, no keyframes)', () => {
  it('has no colour literal in any declaration', () => {
    expect(stripped.match(/#[0-9a-fA-F]{3,8}\b/g)).toBeNull()
    expect(stripped.match(/\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\(/g)).toBeNull()
    // Named colours would pass the two checks above; none is used, only tokens, transparent and currentColor.
    // `black` appears four times, only inside mask-image gradients: a mask reads the alpha channel and paints nothing, so no
    // colour reaches the screen and the stylesheet stays as approved. Anywhere else a named colour fails.
    const maskOnly = stripped.match(/\bblack\b/g) ?? []
    const inMasks = [...stripped.matchAll(/(?:-webkit-)?mask-image\s*:[^;]*;/g)].flatMap((m) => (m[0].match(/\bblack\b/g) ?? []))
    expect(maskOnly.length).toBe(inMasks.length)
    const withoutTokens = stripped.replace(/var\([^)]*\)/g, '').replace(/(?:-webkit-)?mask-image\s*:[^;]*;/g, '')
    expect(withoutTokens.match(/:\s*[^;{}]*\b(?:white|black|red|green|blue|gray|grey|teal|orange|yellow|purple)\b/g)).toBeNull()
  })

  it('has no keyframes and no animation declaration (motion is W4; transitions only, from tokens)', () => {
    expect(stripped).not.toMatch(/@keyframes/)
    expect(stripped).not.toMatch(/\banimation(?:-name)?\s*:/)
    for (const m of stripped.matchAll(/transition\s*:([^;}]*)/g)) {
      const t = m[1] as string
      if (t.trim() === 'none') continue
      expect(t).toMatch(/var\(--dur-(?:fast|base|slow)\)/)
      expect(t).toMatch(/var\(--ease-orbit\)/)
    }
  })

  it('removes every transition under prefers-reduced-motion', () => {
    expect(stripped).toMatch(/@media \(prefers-reduced-motion: reduce\)\s*\{[^}]*transition: none/)
  })

  it('reads only tokens that exist: ds2 colors_and_type, v2 tokens, v2 roles, or its own local properties', () => {
    const ds = ['colors_and_type.css', 'v2/tokens.css', 'v2/roles.css'].map((f) => readFileSync(resolve(here, '../../../design-system-2', f), 'utf8')).join('\n')
    const defined = new Set([...ds.matchAll(/(--[a-zA-Z0-9_-]+)\s*:/g)].map((m) => m[1] as string))
    for (const m of stripped.matchAll(/(--[a-zA-Z0-9_-]+)\s*:/g)) defined.add(m[1] as string)
    const used = [...new Set([...stripped.matchAll(/var\((--[a-zA-Z0-9_-]+)/g)].map((m) => m[1] as string))]
    expect(used.length).toBeGreaterThan(40)
    expect(used.filter((v) => !defined.has(v))).toEqual([])
  })
})

describe('plans.css (acceptance criterion 3: the toggle overlay and the link above it)', () => {
  const rule = (selector: string): Record<string, string> => Object.assign({}, ...baseRules.filter((r) => r.selector.split(',').map((s) => s.trim()).includes(selector)).map((r) => r.decls))

  it('stretches the toggle button over the whole row with ::after', () => {
    const after = rule('.pl-toggle::after')
    expect(after.position).toBe('absolute')
    expect(after.inset).toBe('0')
    expect(after['z-index']).toBe('1')
    // The overlay is positioned against the row, so the row is positioned and the button is not.
    expect(rule('.pl-row').position).toBe('relative')
    expect(rule('.pl-toggle').position).toBeUndefined()
  })

  it('puts the record link above the overlay', () => {
    const link = rule('.pl a.enc-id')
    expect(link.position).toBe('relative')
    expect(Number(link['z-index'])).toBeGreaterThan(Number(rule('.pl-toggle::after')['z-index']))
  })
})

describe('plans.css container query boundaries (card width, not viewport)', () => {
  it('is measured on the card', () => {
    expect(baseRules.find((r) => r.selector === '.pl-card')?.decls['container-type']).toBe('inline-size')
    // 560 twice: the lanes block, then the one-line block that shows the axis label.
    expect(containerBlocks.map((b) => b.minWidth)).toEqual([560, 880, 560])
  })

  // 342: a 390 phone with 24 gutters on each side, which is a card well under 560. 1072: the 1360 desktop main column.
  it.each([
    [342, 'stack', 'none', 'none'],
    [559, 'stack', 'none', 'none'],
    [560, 'two', 'none', 'flex'],
    [879, 'two', 'none', 'flex'],
    [880, 'three', 'grid', 'flex'],
    [1072, 'three', 'grid', 'flex'],
  ])('at %ipx of card width the rows are %s, .pl-dur is %s and the axis label is %s', (width, layout, dur, axisLabel) => {
    const cols = widthRule('.pl-row', 'grid-template-columns', width)
    if (layout === 'stack') expect(cols).toBe('minmax(0, 1fr)')
    else if (layout === 'two') expect(cols).toBe('var(--pl-label) minmax(0, 1fr)')
    else expect(cols).toBe('var(--pl-label) minmax(0, 1fr) var(--pl-dur)')
    expect(widthRule('.pl-dur', 'display', width)).toBe(dur === 'none' ? 'none' : 'grid')
    expect(widthRule('.pl-axis .pl-lab', 'display', width)).toBe(axisLabel)
  })

  it('widens the label column at 880 and gives the track its taller lane at 560', () => {
    expect(widthRule('.pl-lanes', '--pl-label', 559)).toBe('0px')
    expect(widthRule('.pl-lanes', '--pl-label', 560)).toBe('300px')
    expect(widthRule('.pl-lanes', '--pl-label', 880)).toBe('340px')
    expect(widthRule('.pl-lanes', '--pl-dur', 879)).toBe('0px')
    expect(widthRule('.pl-lanes', '--pl-dur', 880)).toBe('132px')
    expect(widthRule('.pl-track', 'height', 559)).toBe('20px')
    expect(widthRule('.pl-track', 'height', 560)).toBe('28px')
  })
})
