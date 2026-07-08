import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

/**
 * ENC-TSK-M26 — regression coverage for two mobile defects confirmed by a
 * live human UAT probe at 526px CSS width against gamma (ENC-ISS-515,
 * ENC-ISS-516), both regressions against closed tasks ENC-TSK-M15/M16:
 *
 *  A. The mobile nav drawer never actually opened. `.ev2-al__nav` had no
 *     explicit `display` in the open state, so the "Menu" toggle flipped
 *     `.ev2-al__nav--collapsed` on/off with no visible effect. AppShell
 *     already computed an explicit open-state wrapper class
 *     (`.ev2-shell--nav-open`) that no CSS rule ever consumed.
 *  B. Card grids (design-system-2 <Cards>, which renders its column count
 *     as an INLINE style) stayed multi-column at mobile widths on routes
 *     that never shipped the `!important` mobile override feed/governance/
 *     docs already had (Projects had no CSS file at all), and unconditional
 *     768px min-widths on the feed/docs search inputs forced horizontal
 *     overflow independent of any grid.
 *
 * jsdom does not run a real CSS cascade/layout engine, so a rendered-DOM
 * assertion can't observe actual `display`/`grid-template-columns` computed
 * values here. Instead this test reads the real shipped stylesheets and
 * asserts the specific selectors/declarations the fix depends on are
 * present and correctly scoped -- cheap, deterministic, and it fails loudly
 * if either defect's CSS is ever reverted or a new route ships a `<Cards>`
 * grid without the mobile override.
 */

const uiV2Src = dirname(fileURLToPath(import.meta.url)) // .../src/shell
const srcRoot = resolve(uiV2Src, '..')

function readSrc(relPath: string): string {
  return readFileSync(resolve(srcRoot, relPath), 'utf8')
}

/** Strip /* ... *\/ CSS comments so assertions can't be fooled by prose that
 *  happens to mention old selectors (e.g. this file's own regression notes). */
function stripCssComments(css: string): string {
  return css.replace(/\/\*[\s\S]*?\*\//g, '')
}

describe('mobile nav drawer (ENC-ISS-515 / defect A)', () => {
  const shellCss = stripCssComments(readSrc('shell/shell.css'))
  const mobileBlockMatch = shellCss.match(/@media \(max-width: 48rem\) \{([\s\S]*?)\n\}\n\n\.ev2-shell__nav-scrim/)
  const mobileBlock = mobileBlockMatch?.[1] ?? ''

  it('has a mobile breakpoint block for the shell nav', () => {
    expect(mobileBlock.length).toBeGreaterThan(0)
  })

  it('hides .ev2-al__nav by default at mobile width, independent of the --collapsed class', () => {
    // Must NOT depend on the fragile double-negative :not(.ev2-al__nav--collapsed)
    // selector that shipped in the regressed version.
    expect(mobileBlock).not.toMatch(/\.ev2-al__nav:not\(/)
    expect(mobileBlock).toMatch(/\.ev2-shell\s+\.ev2-al__nav\s*\{[^}]*display:\s*none/)
  })

  it('shows the nav as an explicit full-screen drawer only when .ev2-shell--nav-open is present', () => {
    expect(mobileBlock).toMatch(/\.ev2-shell--nav-open\s+\.ev2-al__nav\s*\{/)
    const openRuleMatch = mobileBlock.match(/\.ev2-shell--nav-open\s+\.ev2-al__nav\s*\{([^}]*)\}/)
    const openRule = openRuleMatch?.[1] ?? ''
    expect(openRule).toMatch(/display:\s*flex/)
    expect(openRule).toMatch(/position:\s*fixed/)
  })

  it('AppShell wires the open state to both the drawer class and the scrim', () => {
    const appShell = readSrc('shell/AppShell.tsx')
    expect(appShell).toMatch(/ev2-shell--nav-open/)
    expect(appShell).toMatch(/ev2-shell__nav-scrim/)
    expect(appShell).toMatch(/toggleSidebar/)
  })
})

describe('card grid mobile collapse (ENC-ISS-516 / defect B)', () => {
  const gridOverridePattern = /@media \(max-width: 48rem\)[\s\S]*?\.ev2-cards__grid\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\)\s*!important/

  it.each([
    ['routes/home.css', '.home-route'],
    ['routes/projects.css', '.projects-route'],
    ['routes/feed.css', '.feed-route'],
    ['routes/governance.css', '.governance-route'],
    ['routes/docs.css', '.docs-route'],
  ])('%s scopes a single-column mobile override to %s .ev2-cards__grid', (path, routeClass) => {
    const css = readSrc(path)
    expect(css).toMatch(gridOverridePattern)
    expect(css).toContain(`${routeClass} .ev2-cards__grid`)
  })

  it('RecordCard grid is mobile-first single column using minmax(0, 1fr), not a bare 1fr', () => {
    const css = readSrc('components/recordCard.css')
    const baseGridMatch = css.match(/\.ev2-rc-grid\s*\{([^}]*)\}/)
    expect(baseGridMatch?.[1] ?? '').toMatch(/grid-template-columns:\s*minmax\(0,\s*1fr\)/)
    // The 2-col variant must stay opt-in behind the desktop breakpoint.
    const twoColSectionMatch = css.match(/@media \(min-width: 48\.0625rem\) \{[\s\S]*?\.ev2-rc-grid--2col[\s\S]*?\}\n\}/)
    expect(twoColSectionMatch).not.toBeNull()
  })

  it('feed/docs search inputs no longer force a 768px min-width at mobile widths', () => {
    for (const [path, cls] of [
      ['routes/feed.css', '.feed-route__search'],
      ['routes/docs.css', '.docs-route__search'],
    ] as const) {
      const css = readSrc(path)
      const baseRuleMatch = css.match(new RegExp(`(?<!@media[^{]*\\{[^}]*)${cls.replace('.', '\\.')}\\s*\\{([^}]*)\\}`))
      expect(baseRuleMatch, `expected a base (non-media) rule for ${cls} in ${path}`).not.toBeNull()
      expect(baseRuleMatch?.[1] ?? '').not.toMatch(/min-width/)

      const desktopGated = new RegExp(
        `@media \\(min-width: 48\\.0625rem\\) \\{[\\s\\S]*?${cls.replace('.', '\\.')}\\s*\\{[^}]*min-width`,
      )
      expect(css).toMatch(desktopGated)
    }
  })
})
