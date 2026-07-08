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

/** Extract the body of an `@media (...) { ... }` block (or any `{`-opened
 * rule) by counting braces from the header match, rather than relying on a
 * regex guess at what text follows the closing brace. Robust to whatever
 * rules get added/reordered around the block (see ENC-ISS-51x: an earlier
 * version of this test depended on `.ev2-shell__nav-scrim` being the very
 * next selector after the media block, which broke the moment that rule's
 * position was fixed as part of the Band-B drawer-dismiss repair). */
function extractBlock(css: string, headerPattern: RegExp): string {
  const match = css.match(headerPattern)
  if (!match || match.index === undefined) return ''
  const start = match.index + match[0].length
  let depth = 1
  let i = start
  while (i < css.length && depth > 0) {
    if (css[i] === '{') depth++
    else if (css[i] === '}') depth--
    i++
  }
  return css.slice(start, i - 1)
}

describe('mobile nav drawer (ENC-ISS-515 / defect A)', () => {
  const shellCss = stripCssComments(readSrc('shell/shell.css'))
  const mobileBlock = extractBlock(shellCss, /@media \(max-width: 48rem\) \{/)

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

/**
 * Band-B polish (ENC-ISS-51x, io live-probe 2026-07-08 @ ~500px): the drawer
 * opened (ENC-TSK-M26 above), but dismiss was dead. `.ev2-shell__nav-scrim`
 * existed in the DOM with a real onClick handler, yet rendered at 0x0 --
 * untappable -- because an unconditional `.ev2-shell__nav-scrim{display:
 * none}` rule shipped *after* the mobile-scoped override in shell.css. Equal
 * specificity + later source position means that rule always won the
 * cascade, at any viewport. Escape wasn't wired at all. Fixed by moving the
 * default-hidden rule before the media query, and adding a document-level
 * Escape listener scoped to the open state.
 */
describe('drawer dismiss (ENC-ISS-51x / Band-B defect 1: scrim tap + Escape)', () => {
  const shellCss = stripCssComments(readSrc('shell/shell.css'))
  const mobileBlock = extractBlock(shellCss, /@media \(max-width: 48rem\) \{/)
  const appShell = readSrc('shell/AppShell.tsx')

  it('the mobile override gives the scrim real fixed-position geometry, not display:none', () => {
    const scrimRuleMatch = mobileBlock.match(/\.ev2-shell__nav-scrim\s*\{([^}]*)\}/)
    expect(scrimRuleMatch, 'expected a .ev2-shell__nav-scrim rule inside the mobile block').not.toBeNull()
    const scrimRule = scrimRuleMatch?.[1] ?? ''
    expect(scrimRule).toMatch(/display:\s*block/)
    expect(scrimRule).toMatch(/position:\s*fixed/)
    expect(scrimRule).toMatch(/inset:/)
  })

  it('the default-hidden scrim rule sits BEFORE the mobile media query, not after', () => {
    // A same-specificity `.ev2-shell__nav-scrim` rule declared AFTER the
    // mobile block would win the cascade at every viewport and re-zero the
    // scrim (the exact regression this suite guards against). The only safe
    // place for the unconditional `display: none` default is before it.
    const mediaIdx = shellCss.indexOf('@media (max-width: 48rem)')
    expect(mediaIdx).toBeGreaterThan(-1)
    const before = shellCss.slice(0, mediaIdx)
    const after = shellCss.slice(mediaIdx + '@media (max-width: 48rem) {'.length + mobileBlock.length)

    expect(before).toMatch(/\.ev2-shell__nav-scrim\s*\{\s*display:\s*none;?\s*\}/)

    // Strip out any subsequent @media blocks (nested selectors reusing the
    // same class name inside a *different* scoped context are fine) before
    // checking for a stray bare redeclaration.
    let rest = after
    let mediaMatch: RegExpMatchArray | null
    while ((mediaMatch = rest.match(/@media[^{]*\{/))) {
      const idx = mediaMatch.index ?? 0
      const blockBody = extractBlock(rest, /@media[^{]*\{/)
      rest = rest.slice(0, idx) + rest.slice(idx + mediaMatch[0].length + blockBody.length + 1)
    }
    expect(rest).not.toMatch(/\.ev2-shell__nav-scrim/)
  })

  it('the scrim button keeps a real click-to-close handler', () => {
    const scrimBlockMatch = appShell.match(/className="ev2-shell__nav-scrim"[\s\S]{0,200}/)
    expect(scrimBlockMatch).not.toBeNull()
    expect(scrimBlockMatch?.[0] ?? '').toMatch(/onClick=\{[^}]*setSidebarOpen\(false\)[^}]*\}/)
  })

  it('Escape closes the drawer via a document-level keydown listener scoped to the open state', () => {
    expect(appShell).toMatch(/addEventListener\(\s*['"]keydown['"]/)
    const effectMatch = appShell.match(/useEffect\(\(\) => \{[\s\S]*?Escape[\s\S]*?\}, \[[^\]]*\]\)/)
    expect(effectMatch, 'expected a useEffect wiring an Escape keydown handler').not.toBeNull()
    const effectBody = effectMatch?.[0] ?? ''
    expect(effectBody).toMatch(/navigationOpen/)
    expect(effectBody).toMatch(/setSidebarOpen\(false\)/)
    expect(effectBody).toMatch(/removeEventListener\(\s*['"]keydown['"]/)
  })
})

/**
 * Band-B polish (ENC-ISS-51x, defect 3): `.ev2-tabs__bar` (shared
 * design-system-2 Tabs, used by Home's "Recent activity" section among
 * other routes) already declared `overflow-x: auto`, but neither it nor its
 * `.ev2-tabs` wrapper capped their own width -- the human probe measured the
 * bar at 519px against a 452px viewport. Made explicit and contained with
 * `max-width: 100%` on both, so the horizontal scroll stays local to the tab
 * strip instead of bleeding the page.
 */
describe('tabs bar overflow containment (ENC-ISS-51x / Band-B defect 3)', () => {
  const tabsSrc = readSrc('../../design-system-2/v2/components/Tabs/Tabs.jsx')

  it('caps both the tabs wrapper and the scrollable bar to their container width', () => {
    const wrapperRuleMatch = tabsSrc.match(/\.ev2-tabs\{([^}]*)\}/)
    const barRuleMatch = tabsSrc.match(/\.ev2-tabs__bar\{([^}]*)\}/)
    expect(wrapperRuleMatch?.[1] ?? '').toMatch(/max-width:\s*100%/)
    expect(barRuleMatch?.[1] ?? '').toMatch(/max-width:\s*100%/)
    expect(barRuleMatch?.[1] ?? '').toMatch(/overflow-x:\s*auto/)
  })
})

describe('card grid mobile collapse (ENC-ISS-516 / defect B)', () => {
  const gridOverridePattern = /@media \(max-width: 48rem\)[\s\S]*?\.ev2-cards__grid\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\)\s*!important/

  // ENC-TSK-M35: Feed dropped Cloudscape `<Cards>` entirely (dense single
  // column RecordCard variant="feed" rows now, per Feed.dc.html/
  // Enceladus-v4-Feed-Review.md §3-4), so routes/feed.css no longer renders
  // an `.ev2-cards__grid` element at all -- the defect-B regression this
  // suite guards against is structurally impossible there now. Mobile-first
  // single-column is covered instead by the `.ev2-rc-grid` assertion below.
  it.each([
    ['routes/home.css', '.home-route'],
    ['routes/projects.css', '.projects-route'],
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
      // Comments stripped -- ENC-TSK-M38's own doc comments below mention
      // "min-width:0" in prose, which would otherwise false-positive here.
      const css = stripCssComments(readSrc(path))
      const baseRuleMatch = css.match(new RegExp(`(?<!@media[^{]*\\{[^}]*)${cls.replace('.', '\\.')}\\s*\\{([^}]*)\\}`))
      expect(baseRuleMatch, `expected a base (non-media) rule for ${cls} in ${path}`).not.toBeNull()
      // ENC-TSK-M38 added an explicit `min-width: 0` shrink floor to this same
      // base rule (see the "search input + toolbar overflow floor" suite
      // below) -- that's the fix, not a regression of the original bug. What
      // must never come back is a NON-ZERO unconditional min-width forcing a
      // wide box at every viewport.
      const base = baseRuleMatch?.[1] ?? ''
      const nonZeroMinWidth = /min-width:\s*(?!(?:0(?:px|rem|em)?|var\(--space-0\))\s*;)\S/
      expect(base).not.toMatch(nonZeroMinWidth)

      const desktopGated = new RegExp(
        `@media \\(min-width: 48\\.0625rem\\) \\{[\\s\\S]*?${cls.replace('.', '\\.')}\\s*\\{[^}]*min-width`,
      )
      expect(css).toMatch(desktopGated)
    }
  })
})

/**
 * ENC-TSK-M23 (FND-03, cutover-blocking) -- Record Details mobile hub.
 * Same static-CSS-assertion approach as the suites above: jsdom has no real
 * cascade, so this reads the shipped recordDetailHub.css and RecordDetailHub
 * component source directly.
 */
describe('record detail hub sticky action bar (ENC-TSK-M23)', () => {
  const hubCss = stripCssComments(readSrc('components/recordDetailHub.css'))
  const hubSrc = readSrc('components/RecordDetailHub.tsx')

  it('ships a mobile-base sticky bottom action bar pinned to the viewport', () => {
    const stickyMatch = hubCss.match(/\.ev2-rdh__actionbar--sticky\s*\{([^}]*)\}/)
    expect(stickyMatch, 'expected a .ev2-rdh__actionbar--sticky rule').not.toBeNull()
    const stickyRule = stickyMatch?.[1] ?? ''
    expect(stickyRule).toMatch(/position:\s*fixed/)
    expect(stickyRule).toMatch(/bottom:\s*0/)
  })

  it('folds the action bar inline and hides the fixed bar at the desktop breakpoint', () => {
    const desktopBlock = extractBlock(hubCss, /@media \(min-width: 64rem\) \{/)
    expect(desktopBlock.length).toBeGreaterThan(0)
    expect(desktopBlock).toMatch(/\.ev2-rdh__actionbar--inline\s*\{[^}]*display:\s*flex/)
    expect(desktopBlock).toMatch(/\.ev2-rdh__actionbar--sticky\s*\{[^}]*display:\s*none/)
  })

  it('renders the sticky bar as a real toolbar with a Copy ID action', () => {
    expect(hubSrc).toMatch(/ev2-rdh__actionbar--sticky/)
    expect(hubSrc).toMatch(/role="toolbar"/)
    expect(hubSrc).toMatch(/Copy ID/)
  })

  it('keeps the hub and its vitals grid capped to their container width (no horizontal scroll)', () => {
    const rootMatch = hubCss.match(/\.ev2-rdh\s*\{([^}]*)\}/)
    expect(rootMatch?.[1] ?? '').toMatch(/max-width:\s*100%/)
    const vitalsMatch = hubCss.match(/\.ev2-rdh__vitals\s*\{([^}]*)\}/)
    expect(vitalsMatch?.[1] ?? '').toMatch(/grid-template-columns:\s*minmax\(0,\s*1fr\)/)
    const bodyMatch = hubCss.match(/\.ev2-rdh__body\s*\{([^}]*)\}/)
    expect(bodyMatch?.[1] ?? '').toMatch(/max-width:\s*100%/)
  })

  it('reserves bottom padding on mobile so the fixed bar never occludes content', () => {
    const rootMatch = hubCss.match(/\.ev2-rdh\s*\{([^}]*)\}/)
    expect(rootMatch?.[1] ?? '').toMatch(/padding-bottom:/)
  })
})

/**
 * ENC-TSK-M38 -- the "Search records or saved name…" input (FeedRoute) and
 * its Docs-route twin sat inside a `flex: 1` toolbar item with no explicit
 * `min-width`. `.ev2-al__content` (AppLayout.jsx) already floors its own
 * cross-axis auto-minimum with `min-width: 0`, but that guarantee stops at
 * the first descendant that doesn't repeat it -- a flex item's automatic
 * minimum size defaults to its content's min-content width, not 0, unless
 * the item (or a shrink-blocking ancestor) says so explicitly. The nested
 * Autosuggest -> Input -> <input> chain sets `min-width: 0` only on the
 * innermost field, which is fragile: any future sibling (an icon, an
 * inline suggestion chip) breaks the guarantee again. This suite pins the
 * floor at every level of the chain -- the route root, the toolbar, and the
 * search box itself -- for both routes, plus a root-level sweep across the
 * remaining flex-column route surfaces (ENC-TSK-M38 AC-2: route sweep).
 */
describe('search input + toolbar overflow floor (ENC-TSK-M38)', () => {
  it.each([
    ['routes/feed.css', '.feed-route', '.feed-route__toolbar', '.feed-route__search'],
    ['routes/docs.css', '.docs-route', '.docs-route__toolbar', '.docs-route__search'],
  ] as const)('%s floors the route root, toolbar, and search box to min-width: 0', (path, rootCls, toolbarCls, searchCls) => {
    const css = stripCssComments(readSrc(path))
    for (const cls of [rootCls, toolbarCls, searchCls]) {
      const escaped = cls.replace('.', '\\.')
      const ruleMatch = css.match(new RegExp(`${escaped}\\s*\\{([^}]*)\\}`))
      expect(ruleMatch, `expected a base rule for ${cls} in ${path}`).not.toBeNull()
      expect(ruleMatch?.[1] ?? '').toMatch(/min-width:\s*(var\(--space-0\)|0)/)
    }
  })

  it('the search box base rule keeps its min-width:0 floor BEFORE the desktop min-width opt-in', () => {
    // Regression guard: a later, higher-specificity or later-source-order
    // rule re-introducing an unconditional min-width would silently undo
    // the floor above at exactly the narrow widths this task targets.
    for (const [path, cls] of [
      ['routes/feed.css', '.feed-route__search'],
      ['routes/docs.css', '.docs-route__search'],
    ] as const) {
      const css = stripCssComments(readSrc(path))
      const floorIdx = css.search(new RegExp(`${cls.replace('.', '\\.')}\\s*\\{[^}]*min-width:\\s*(var\\(--space-0\\)|0)`))
      const desktopGateIdx = css.indexOf('@media (min-width: 48.0625rem)')
      expect(floorIdx).toBeGreaterThan(-1)
      expect(desktopGateIdx).toBeGreaterThan(-1)
      expect(floorIdx).toBeLessThan(desktopGateIdx)
    }
  })

  it.each([
    ['routes/coordination.css', '.coordination-route'],
    ['routes/governance.css', '.governance-route'],
    ['routes/skillLibrary.css', '.ev2-skill-library'],
  ] as const)('route sweep: %s floors %s to min-width: 0', (path, rootCls) => {
    const css = stripCssComments(readSrc(path))
    const ruleMatch = css.match(new RegExp(`${rootCls.replace('.', '\\.')}\\s*\\{([^}]*)\\}`))
    expect(ruleMatch, `expected a base rule for ${rootCls} in ${path}`).not.toBeNull()
    expect(ruleMatch?.[1] ?? '').toMatch(/min-width:\s*(var\(--space-0\)|0)/)
  })
})
