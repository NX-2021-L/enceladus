import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

/**
 * DVP-TSK-A12 (io, iPhone review of gamma): the search controls on /feed and /docs.
 * Source and CSS contracts (no browser in CI): no "Pin as related", the kit's design-system typography reaches the
 * controls, the iOS focus-zoom guard runs at boot, "hide toggles" is the only toggle, and the frozen controls block has
 * a clean sticky path to the page scroller.
 */
const srcRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const uiRoot = resolve(srcRoot, '..')
const read = (rel: string) => readFileSync(resolve(srcRoot, rel), 'utf8')
const stripComments = (source: string) => source.replace(/\/\*[\s\S]*?\*\//g, '')
const css = (rel: string) => stripComments(read(rel))

function* walk(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    if (name === 'fixtures' || name === '__fixtures__') continue
    const full = join(dir, name)
    if (statSync(full).isDirectory()) yield* walk(full)
    else yield full
  }
}

describe('no "Pin as related"', () => {
  it('is gone from the row card, both pages and the stylesheet', () => {
    for (const f of ['feed/FeedRowCard.tsx', 'feed/FeedSearchPage.tsx', 'routes/DocsSearchPage.tsx', 'routes/feed.css']) {
      expect(read(f), f).not.toMatch(/Pin as related|feed-route__pin|feed-route__row-extras|canPin|\bonPin\b|pinToSelected|PinState|\bpins\b/)
    }
    // the evidence chips stay, directly under the card
    expect(read('feed/FeedRowCard.tsx')).toMatch(/<SignalReadout /)
  })
})

describe('typography: the kit theme supplies the design-system tokens', () => {
  const theme = join(uiRoot, 'node_modules', '@io-kit', 'search-ui', 'dist', 'themes', 'enceladus.css')
  it('both pages import the prebuilt enceladus search theme (kit 1.0.4 emits the font tokens)', () => {
    for (const f of ['feed/FeedSearchPage.tsx', 'routes/DocsSearchPage.tsx']) {
      expect(read(f), f).toMatch(/import '@io-kit\/search-ui\/themes\/enceladus\.css'/)
    }
    expect(existsSync(theme)).toBe(true)
    const themeCss = readFileSync(theme, 'utf8')
    expect(themeCss).toMatch(/--io-search-control-font-family:\s*'Space Grotesk'/)
    expect(themeCss).toMatch(/--io-search-control-font-size:\s*0\.875rem/)
    expect(themeCss).toMatch(/--io-search-control-font-weight:\s*500/)
    expect(themeCss).toMatch(/--io-search-input-font-family:\s*'Inter'/)
    expect(themeCss).toMatch(/--io-search-input-font-size:\s*0\.875rem/)
  })
  it('no host stylesheet restyles the search type (no io-search font rule, no 16px coarse-pointer bump)', () => {
    for (const file of walk(srcRoot)) {
      if (!file.endsWith('.css')) continue
      const source = stripComments(readFileSync(file, 'utf8'))
      for (const [, selector, body] of source.matchAll(/([^{}@]+)\{([^{}]*)\}/g)) {
        if (!/io-search/.test(selector ?? '')) continue
        expect(body, `${file} ${selector?.trim()}`).not.toMatch(/font-(size|family|weight)/)
      }
      expect(source, file).not.toMatch(/--io-search-(control|input|meta)-font/)
    }
  })
  it('the iOS focus-zoom guard runs once at boot, before the first render', () => {
    const main = read('main.tsx')
    expect(main).toMatch(/import \{ installIosFocusZoomGuard(, watchForUpdates)? \} from '@io-kit\/shell'/)
    expect(main.match(/^installIosFocusZoomGuard\(\)/gm)).toHaveLength(1)
    expect(main.indexOf('installIosFocusZoomGuard()')).toBeLessThan(main.indexOf('createRoot(rootEl)'))
  })
})

describe('service-worker update freshness (DVP-TSK-A14)', () => {
  it('re-checks for a new worker on foreground via the kit watcher', () => {
    const main = read('main.tsx')
    expect(main).toMatch(/onRegisteredSW\(_url, registration\) \{\s*if \(registration\) watchForUpdates\(registration\)/)
  })
})

describe('hide / show toggles', () => {
  it('the frame owns the state, renders the kit link in the PageHeader and turns the kit link off', () => {
    const frame = read('search/SearchSplitPage.tsx')
    expect(frame).toMatch(/useControlsHidden\(\{ restoreKey: search\.restoreKey \}\)/)
    expect(frame).toMatch(/<ControlsToggle \{\.\.\.toggle\} \/>/)
    expect(frame).toMatch(/controlsToggle=\{false\}/)
    expect(frame).toMatch(/controlsHidden=\{controls\.hidden\}/)
    expect(frame).toMatch(/onControlsHiddenChange=\{controls\.setHidden\}/)
    expect(frame).toMatch(/controlsId=\{controls\.controlsId\}/)
  })
  it('persists per page: restoreKey feed and docs', () => {
    expect(read('feed/FeedSearchPage.tsx')).toMatch(/restoreKey: 'feed'/)
    expect(read('routes/DocsSearchPage.tsx')).toMatch(/restoreKey: 'docs'/)
  })
})

describe('frozen controls: sticky to the page scroller below 960px', () => {
  it('the sticky edge is 0 (the app bar is outside the scroller) and the bg is the page background token', () => {
    const split = css('search/searchSplit.css')
    // DVP-TSK-A14: the stuck edge is pulled up by the page scroller's 16px top padding, with an equal opaque band.
    expect(split).toMatch(/\.ev2-fill\s*\{[^}]*--io-search-sticky-top:\s*calc\(-1 \* var\(--space-4\)\);[^}]*--io-search-sticky-bg:\s*var\(--enc-void\)/)
    expect(split).toMatch(/@media \(max-width: 959\.98px\)\s*\{[\s\S]*\.ev2-fill \.io-search__controls\s*\{[^}]*padding-block-start:\s*var\(--space-4\);[^}]*margin-block-start:\s*calc\(-1 \* var\(--space-4\)\)/)
    const tokens = readFileSync(resolve(uiRoot, '..', 'design-system-2', 'colors_and_type.css'), 'utf8')
    expect(tokens).toMatch(/--enc-void:\s*#0A0A0F/i)
  })
  it('no ancestor between .io-search__controls and .ev2-al__content clips, scrolls, contains or transforms below 960px', () => {
    const raw = ['shell/shell.css', 'search/searchSplit.css', 'routes/feed.css', 'routes/docs.css'].map(css).join('\n')
    const wide = /@media \(min-width: 960px\)\s*\{(?:[^{}]*\{[^{}]*\})*\s*\}/g
    // self-check: the fill rule that clips the page scroller exists, and only inside the 960px+ block
    expect(raw).toMatch(/\.ev2-al__content\[data-ev2-fill\]\s*\{\s*overflow: hidden;/)
    const narrow = raw.replace(wide, '')
    expect(narrow).not.toMatch(/\.ev2-al__content\[data-ev2-fill\]\s*\{\s*overflow: hidden;/)
    const ancestors = /\.(ev2-al__content|ev2-shell__main|ev2-fill|io-split|io-split__own|io-split__primary|feed-route|docs-route)(?![\w-])/
    const breaker = /(^|[;\s])(overflow(-x|-y)?|contain|content-visibility|transform|filter|perspective|clip-path)\s*:/
    for (const [, selector, body] of narrow.matchAll(/([^{}@]+)\{([^{}]*)\}/g)) {
      if (!ancestors.test(selector ?? '')) continue
      expect(body, selector?.trim()).not.toMatch(breaker)
    }
  })
})
