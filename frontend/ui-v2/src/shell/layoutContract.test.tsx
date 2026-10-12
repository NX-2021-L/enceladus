import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { act, type ReactElement } from 'react'
import { createRoot } from 'react-dom/client'
import { describe, expect, it } from 'vitest'
import { PageHeader } from '../components/PageHeader'
import { Table } from '../components/StackedTable'
import { Tabs } from '../components/StripTabs'

/**
 * DVP-TSK-A09 (R16 clean lines). jsdom has no layout engine, so the geometry (search input top == detail card top, 0px
 * delta) is verified live on gamma; this contract pins the structure that produces it: one scroll owner per region,
 * the SplitPage frame on /feed and /docs, tabs and tables as strips, stacked tables on phones, ONE page header.
 */
async function mount(el: ReactElement) {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  const container = document.createElement('div')
  document.body.appendChild(container)
  const root = createRoot(container)
  await act(async () => {
    root.render(el)
  })
  return { container }
}
const srcRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const read = (rel: string) => readFileSync(resolve(srcRoot, rel), 'utf8')
const stripComments = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, '')
const css = (rel: string) => stripComments(read(rel))
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const ruleBody = (source: string, selector: string) => source.match(new RegExp(`${escapeRe(selector)}\\s*\\{([^}]*)\\}`))?.[1] ?? ''

describe('split classes on /feed and /docs', () => {
  const frame = read('search/SearchSplitPage.tsx')
  it('the shared frame is the kit SplitPage with scrolling results and a portalled page header', () => {
    expect(frame).toMatch(/import \{ SplitPage \} from '@io-kit\/shell\/react'/)
    expect(frame).toMatch(/scrollResults/)
    expect(frame).toMatch(/scrollPrimary=\{false\}/)
    expect(frame).toMatch(/createPortal\(/)
    expect(frame).toMatch(/<PageHeader /)
    expect(frame).not.toMatch(/loadMore/) // auto-load (IntersectionObserver sentinel) stays the kit default
  })
  it('/feed and /docs render through it; /docs is single column; /feed has the reading pane as the secondary', () => {
    const feed = read('feed/FeedSearchPage.tsx')
    const docs = read('routes/DocsSearchPage.tsx')
    expect(feed).toMatch(/<SearchSplitPage/)
    expect(docs).toMatch(/<SearchSplitPage/)
    expect(docs).toMatch(/\bsingle\b/)
    expect(feed).toMatch(/secondary:/)
    expect(feed).toMatch(/className="feed-route__pane"/)
    for (const src of [feed, docs]) expect(src).not.toMatch(/CollectionSearch\b[^\n]*cloudscape|list-scroll|feed-route__split/)
  })
  it('fill routes: from 960px the page scroller does not scroll', () => {
    const shellCss = css('shell/shell.css')
    expect(shellCss).toMatch(/@media \(min-width: 960px\)[\s\S]*\.ev2-al__content\[data-ev2-fill\]\s*\{\s*overflow: hidden;/)
    expect(read('shell/AppShell.tsx')).toMatch(/FILL_ROUTES = \['\/feed', '\/docs'\]/)
    expect(read('shell/AppShell.tsx')).toMatch(/toggleAttribute\('data-ev2-fill'/)
    expect(css('search/searchSplit.css')).toMatch(/grid-template-areas: 'header' 'primary'/)
  })
})

describe('no nested scrollers', () => {
  it('feed.css has no .feed-route__list-scroll and no max-height scroller', () => {
    const feedCss = css('routes/feed.css')
    expect(feedCss).not.toMatch(/feed-route__list-scroll/)
    expect(feedCss).not.toMatch(/max-height/)
    expect(feedCss).not.toMatch(/feed-route__split/)
  })
  it('the record detail hub body clips instead of creating a second scroller', () => {
    const body = ruleBody(css('components/recordDetailHub.css'), '.ev2-rdh__body')
    expect(body).toMatch(/overflow-x: clip/)
    expect(body).not.toMatch(/overflow(-y)?: (auto|scroll|hidden)/)
  })
})

describe('one scroll owner per region', () => {
  const shell = read('shell/AppShell.tsx')
  it('the page scroller is .io-scroll with scroll activity, and the nav panel is its own .io-scroll', () => {
    expect(shell).toMatch(/classList\.add\('io-scroll'\)/)
    expect(shell).toMatch(/useScrollActivity\(scrollerRef\)/)
    expect(shell).toMatch(/<ScrollRegion className="ev2-shell__nav">/)
    const navCss = css('shell/shell.css')
    expect(ruleBody(navCss, '.ev2-shell__nav')).toMatch(/flex: 1 1 auto/)
    expect(navCss).toMatch(/\.ev2-al__nav:not\(\.ev2-al__nav--collapsed\)\s*\{[^}]*align-self: stretch/)
    expect(navCss).toMatch(/\.ev2-al__nav:not\(\.ev2-al__nav--collapsed\)\s*\{[^}]*var\(--io-safe-bottom\)/)
  })
  it('html carries data-io-scrollbars and the enceladus theme maps the --io-scrollbar-* tokens', () => {
    expect(read('../index.html')).toMatch(/<html [^>]*\bdata-io-scrollbars\b/)
    const styles = read('styles.css')
    expect(styles).toMatch(/--io-scrollbar-thumb: color-mix\(in srgb, var\(--enc-teal\)/)
    expect(styles).toMatch(/--io-scrollbar-thumb-hover: color-mix\(in srgb, var\(--enc-teal-light\)/)
    expect(styles).toMatch(/--io-scrollbar-track: transparent/)
    expect(styles).toMatch(/design-system-2\/v2\/tokens\.css/)
  })
})

describe('tabs are a strip', () => {
  it('the bar is overflow-y hidden with no scrollbar, never overflow-y auto', () => {
    const strips = css('components/strips.css')
    const bar = ruleBody(strips, '.ev2-tabs-strip .ev2-tabs__bar')
    expect(bar).toMatch(/overflow-y: hidden/)
    expect(bar).toMatch(/scrollbar-width: none/)
    expect(bar).not.toMatch(/overflow-y: (auto|scroll)/)
  })
  it('every Tabs consumer uses the strip wrapper, not the raw ds2 Tabs', () => {
    for (const f of ['components/RecordDetailHub.tsx', 'routes/CoordinationRoute.tsx', 'routes/HomeRoute.tsx']) {
      const src = read(f)
      expect(src).toMatch(/import \{ Tabs \} from '(\.\.\/components|\.)\/StripTabs'/)
      expect(src).not.toMatch(/import \{[^}]*\bTabs\b[^}]*\} from '[./]*design-system'/)
    }
  })
  it('renders the bar as .io-scroll-x', async () => {
    const { container } = await mount(<Tabs tabs={[{ id: 'a', label: 'A', content: 'x' }, { id: 'b', label: 'B', content: 'y' }]} />)
    const bar = container.querySelector('.ev2-tabs__bar')
    expect(bar?.classList.contains('io-scroll-x')).toBe(true)
  })
})

describe('tables: stacked below 688px, strips above', () => {
  it('strips.css stacks rows with data-label below 688px (42.99rem)', () => {
    const strips = css('components/strips.css')
    expect(strips).toMatch(/@media \(max-width: 42\.99rem\)/)
    expect(strips).toMatch(/content: attr\(data-label\)/)
    expect(strips).toMatch(/\.ev2-table tbody td\s*\{[^}]*display: flex/)
    expect(strips).toMatch(/\.ev2-table-stack \.ev2-table__scroll\s*\{[^}]*overflow: visible/)
  })
  it('every Table consumer uses the stacked wrapper', () => {
    for (const f of ['routes/SkillLibraryRoute.tsx', 'routes/ChangelogRoute.tsx', 'routes/AgentDetailRoute.tsx']) {
      const src = read(f)
      expect(src).toMatch(/import \{ Table \} from '\.\.\/components\/StackedTable'/)
      expect(src).not.toMatch(/import \{[^}]*\bTable\b[^}]*\} from '[./]*design-system'/)
    }
  })
  it('labels every cell from its column header and makes the scroller a strip', async () => {
    const { container } = await mount(
      <Table
        columnDefinitions={[
          { id: 'id', header: 'ID', cell: (r: { id: string; n: string }) => r.id },
          { id: 'n', header: 'Name', cell: (r: { id: string; n: string }) => r.n },
        ]}
        items={[{ id: 'a', n: 'Alpha' }]}
      />,
    )
    expect(container.querySelector('.ev2-table__scroll')?.classList.contains('io-scroll-x')).toBe(true)
    const cells = Array.from(container.querySelectorAll('tbody td')).map((td) => td.getAttribute('data-label'))
    expect(cells).toEqual(['ID', 'Name'])
  })
})

describe('one page header component', () => {
  const routes = [
    'routes/ProjectsRoute.tsx',
    'routes/GovernanceRoute.tsx',
    'routes/CoordinationRoute.tsx',
    'routes/SkillLibraryRoute.tsx',
    'routes/ChangelogRoute.tsx',
    'routes/EscalationsRoute.tsx',
    'routes/NotificationSettingsRoute.tsx',
    'routes/HomeRoute.tsx',
    'routes/PlaceholderRoute.tsx',
    'search/SearchSplitPage.tsx',
  ]
  it('every route renders <PageHeader> and none keeps a bespoke h1', () => {
    for (const f of routes) {
      const src = read(f)
      expect(src, f).toMatch(/<PageHeader\b/)
      expect(src, f).not.toMatch(/<h1\b/)
      expect(src, f).not.toMatch(/<Header\s+variant="h1"/)
      expect(src, f).not.toMatch(/route__title|ev2-placeholder__title|route__eyebrow/)
    }
  })
  it('the title is the ds2 h1 type and the count is appended muted: "Feed (5,573)"', async () => {
    const { container } = await mount(<PageHeader title="Feed" count={5573} />)
    const h1 = container.querySelector('h1.ev2-header__title')
    expect(h1?.textContent).toBe('Feed (5,573)')
    expect(container.querySelector('.ev2-page-header .ev2-header__counter')?.textContent).toBe('(5,573)')
    expect(css('components/pageHeader.css')).toMatch(/\.ev2-header__counter\s*\{[^}]*color: var\(--fg-muted\)/)
  })
})
