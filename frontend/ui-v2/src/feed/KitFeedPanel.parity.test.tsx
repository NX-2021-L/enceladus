/**
 * DVP-TSK-931 AC2: KitFeedPanel's list region is the legacy feed's list region. The legacy list is
 * `<div class="ev2-rc-grid">{hits.map(renderFeedRow)}</div>` (narrow) or the rows directly inside
 * `.feed-route__list-scroll` (wide); this test renders that markup from the same fixture and compares it with the
 * real KitFeedPanel (real @io-kit/feed engine + FeedList over a replayed feed_query response) after removing the
 * kit's own wrappers (data-feed, data-feed-id, list reset style). No @testing-library here: createRoot + act.
 */
import { act, type ReactNode } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { SearchResultHit } from '../types/search'
import type { FeedCorpusRecord } from './enceladusFeedSource'

vi.mock('@tanstack/react-router', () => ({
  useSearch: () => ({ q: '', f: '', op: 'and', sort: 'updated', scroll: 0 }),
  useNavigate: () => () => {},
  Link: ({ children, className, to }: { children: ReactNode; className?: string; to?: unknown }) => (
    <a className={className} data-to={String(to)}>
      {children}
    </a>
  ),
}))
const NO_EVENTS: never[] = []
vi.mock('../realtime/RealtimeFeedProvider', () => ({ useRealtimeFeedEvents: () => NO_EVENTS }))
vi.mock('../api/projectRegistry', () => ({
  projectRegistryQueryOptions: { queryKey: ['test-projects'], queryFn: async () => [] },
  resolveProjectFromRecordId: () => null,
}))
vi.mock('../api/feedCorpusQueryOptions', () => ({
  feedCorpusQueryOptions: () => ({ queryKey: ['test-corpus-total'], queryFn: async () => ({ total_matches: 4 }) }),
}))
vi.mock('../routes/FeedReadingPane', () => ({ FeedReadingPane: () => null }))
vi.mock('../routes/RecentlyViewedNav', () => ({ RecentlyViewedNav: () => null }))
vi.mock('../search/FeedPropertyFilter', () => ({ FeedPropertyFilter: () => null }))
vi.mock('../search/useTieredSearch', () => ({
  useTieredSearch: (_p: unknown, corpus: Array<Record<string, unknown>>) => ({
    hits: corpus.map((r) => ({ ...r, tier: 'local' })),
    evidenceById: new Map(),
    availability: null,
    degraded: false,
    hybridPending: false,
    hybridError: null,
    serverDown: false,
  }),
}))
// Replay one feed_query head page; drop IndexedDB persistence (jsdom has none).
vi.mock('./enceladusFeedSource', async (orig) => {
  const a = await orig<typeof import('./enceladusFeedSource')>()
  const { ITEMS } = await import('./KitFeedPanel.fixture')
  return {
    ...a,
    createEnceladusFeedSource: (o: object) =>
      a.createEnceladusFeedSource({
        ...o,
        apiBase: '/api/v1',
        fetch: async (url: string) => ({
          ok: true,
          status: 200,
          json: async () =>
            url.includes('/delta') ? { latest_version_seq: 4, items: [], tombstones: [] } : { items: ITEMS, next_cursor: null },
        }),
      }),
  }
})
vi.mock('@io-kit/feed/idb', () => ({ createIdbStorage: () => undefined }))
vi.mock('@io-kit/feed/react', async (orig) => {
  const a = await orig<typeof import('@io-kit/feed/react')>()
  return { ...a, createFeed: (o: { persist?: unknown }) => a.createFeed({ ...o, persist: undefined } as never) }
})

import KitFeedPanel, { toSearchRow } from './KitFeedPanel'
import { renderFeedRow } from './FeedRowCard'
import { ITEMS } from './KitFeedPanel.fixture'

;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

let container: HTMLDivElement
let root: Root
const wide = (matches: boolean) => {
  window.matchMedia = ((media: string) => ({
    matches,
    media,
    addEventListener: () => {},
    removeEventListener: () => {},
  })) as never
}
const hits = (): SearchResultHit[] => ITEMS.map((i: FeedCorpusRecord) => ({ ...toSearchRow(i)!, tier: 'local' as const }))
const unwrap = (el: Element) => el.replaceWith(...Array.from(el.childNodes))

async function mount(ui: ReactNode) {
  await act(async () => {
    root.render(<QueryClientProvider client={new QueryClient()}>{ui}</QueryClientProvider>)
    await new Promise((r) => setTimeout(r, 30))
  })
}

beforeEach(() => {
  container = document.createElement('div')
  document.body.appendChild(container)
  root = createRoot(container)
})
afterEach(() => {
  act(() => root.unmount())
  container.remove()
})

describe('KitFeedPanel renders the legacy feed page', () => {
  it('keeps the legacy header, search, sort, saved searches and meta line', async () => {
    wide(false)
    await mount(<KitFeedPanel />)
    expect(container.querySelector('h1.feed-route__title')?.textContent).toBe('Results')
    expect(container.querySelector('.feed-route__eyebrow')?.textContent).toMatch(/^FEED · /)
    expect(container.querySelector('.feed-route__toolbar')).not.toBeNull()
    expect(container.querySelector('input[placeholder="Search records or saved name…"]')).not.toBeNull()
    expect(container.querySelector('.feed-route__sort select')).not.toBeNull()
    expect(container.querySelector('.feed-route__meta')?.textContent).toContain(`${ITEMS.length} hits`)
    expect(container.querySelector('.ev2-kitfeed')).toBeNull()
  })

  it('narrow: the list region equals the legacy ev2-rc-grid of record cards', async () => {
    wide(false)
    const cx = { projects: [], isWide: false, selectedHit: null, onSelect() {}, onLeave() {}, tiered: { evidenceById: new Map(), availability: null }, pins: {}, onPin() {} }
    const ref = document.createElement('div')
    document.body.appendChild(ref)
    const refRoot = createRoot(ref)
    act(() => refRoot.render(<div className="ev2-rc-grid">{hits().map((h) => renderFeedRow(h, cx as never))}</div>))
    await mount(<KitFeedPanel />)
    const region = container.querySelector('[data-feed]')!
    region.querySelectorAll('[data-feed-id]').forEach(unwrap)
    const list = region.firstElementChild!
    list.removeAttribute('style')
    expect(list.outerHTML).toBe(ref.innerHTML)
    expect(list.querySelectorAll('article, [class*="rc-"]').length).toBeGreaterThan(0)
    expect(list.textContent).toContain('ENC-TSK-1120')
    act(() => refRoot.unmount())
    ref.remove()
  })

  it('wide: the list scroller holds the same cards, selection on the first hit, pin on the rest, reading pane slot', async () => {
    wide(true)
    const hs = hits()
    const cx = { projects: [], isWide: true, selectedHit: hs[0]!, onSelect() {}, onLeave() {}, tiered: { evidenceById: new Map(), availability: null }, pins: {}, onPin() {} }
    const ref = document.createElement('div')
    document.body.appendChild(ref)
    const refRoot = createRoot(ref)
    act(() => refRoot.render(<div className="feed-route__list-scroll">{hs.map((h) => renderFeedRow(h, cx as never))}</div>))
    await mount(<KitFeedPanel />)
    const scroller = container.querySelector('.feed-route__list-scroll')!
    expect(container.querySelector('.feed-route__split .feed-route__pane')).not.toBeNull()
    scroller.querySelectorAll('[data-feed-id]').forEach(unwrap)
    const list = scroller.querySelector('[data-feed] > div')!
    unwrap(list)
    scroller.querySelectorAll('[data-feed]').forEach(unwrap)
    expect(scroller.outerHTML).toBe(ref.firstElementChild!.outerHTML)
    expect(scroller.querySelectorAll('.feed-route__pin').length).toBeGreaterThan(0)
    act(() => refRoot.unmount())
    ref.remove()
  })
})
